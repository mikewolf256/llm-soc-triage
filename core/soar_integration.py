"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

SOAR (Security Orchestration, Automation and Response) Integration

Sends high-confidence IDOR detection events to SOAR platforms for
automated incident response and auto-hold actions.

Supported SOAR Platforms:
- Generic webhook (any platform with REST API)
- Splunk SOAR (Phantom)
- Palo Alto XSOAR (Cortex)
- IBM Resilient
- ServiceNow SecOps

Configuration:
    Set environment variables:
    - SOAR_WEBHOOK_URL: SOAR incident creation endpoint
    - SOAR_API_KEY: Authentication token
    - SOAR_PLATFORM: Platform type (generic, splunk, xsoar, etc.)
"""

import httpx
import logging
import os
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum

from .schema.web_telemetry import IDORDetectionEvent, AccessAttemptResult
from .telemetry_scrubber import scrub_event_for_soar


logger = logging.getLogger(__name__)


class SOARPlatform(str, Enum):
    """Supported SOAR platforms"""
    GENERIC = "generic"  # Generic webhook
    SPLUNK = "splunk"  # Splunk SOAR (Phantom)
    XSOAR = "xsoar"  # Palo Alto Cortex XSOAR
    RESILIENT = "resilient"  # IBM Resilient
    SERVICENOW = "servicenow"  # ServiceNow SecOps


class SOARIntegration:
    """
    SOAR integration for IDOR detection alerts.
    
    Sends detection events to SOAR platforms with automatic retry logic,
    payload formatting, and authentication.
    
    Usage:
        from core.soar_integration import SOARIntegration
        
        soar = SOARIntegration(
            webhook_url="https://soar.company.com/api/incidents",
            api_key="secret_key",
            platform=SOARPlatform.GENERIC
        )
        
        # Send alert
        result = await soar.send_alert(detection_event)
        if result.success:
            logger.info(f"Alert sent: {result.incident_id}")
    """
    
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        api_key: Optional[str] = None,
        platform: SOARPlatform = SOARPlatform.GENERIC,
        timeout: int = 10,
        retry_attempts: int = 3,
    ):
        """
        Initialize SOAR integration.
        
        Args:
            webhook_url: SOAR incident creation endpoint (or env SOAR_WEBHOOK_URL)
            api_key: Authentication token (or env SOAR_API_KEY)
            platform: SOAR platform type (or env SOAR_PLATFORM)
            timeout: HTTP request timeout in seconds
            retry_attempts: Number of retry attempts on failure
        """
        self.webhook_url = webhook_url or os.getenv("SOAR_WEBHOOK_URL")
        self.api_key = api_key or os.getenv("SOAR_API_KEY")
        self.platform = SOARPlatform(os.getenv("SOAR_PLATFORM", platform))
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        
        if not self.webhook_url:
            logger.warning(
                "SOAR webhook URL not configured. "
                "Set SOAR_WEBHOOK_URL environment variable."
            )
    
    def is_configured(self) -> bool:
        """Check if SOAR integration is properly configured."""
        return bool(self.webhook_url)
    
    async def send_alert(
        self,
        event: IDORDetectionEvent,
        auto_hold: bool = True,
        scrub_pii_for_soar: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Send IDOR detection event to SOAR platform.
        
        Args:
            event: Detection event to send
            auto_hold: Whether to trigger auto-hold action
            scrub_pii_for_soar: Scrub PII before sending (default: from SCRUB_PII_FOR_SOAR env)
        
        Returns:
            dict: Result with success status and incident ID
                {
                    "success": True,
                    "incident_id": "INC-12345",
                    "message": "Alert sent successfully"
                }
        """
        if not self.is_configured():
            logger.error("SOAR integration not configured, cannot send alert")
            return {
                "success": False,
                "error": "SOAR webhook URL not configured"
            }
        
        # Check if PII scrubbing is enabled
        _scrub = scrub_pii_for_soar if scrub_pii_for_soar is not None \
                 else os.getenv("SCRUB_PII_FOR_SOAR", "false").lower() == "true"
        
        if _scrub:
            logger.info(f"Scrubbing PII from event {event.event_id} before SOAR transmission")
            event = scrub_event_for_soar(event)
        
        # Format payload for platform
        payload = self._format_payload(event, auto_hold)
        
        # Send with retry logic
        for attempt in range(self.retry_attempts):
            try:
                result = await self._send_request(payload)
                
                logger.info(
                    f"SOAR alert sent successfully: {event.event_id} "
                    f"(incident: {result.get('incident_id')})"
                )
                
                return {
                    "success": True,
                    "incident_id": result.get("incident_id"),
                    "message": "Alert sent successfully",
                    "attempt": attempt + 1,
                }
            
            except httpx.HTTPError as e:
                logger.warning(
                    f"SOAR webhook attempt {attempt + 1}/{self.retry_attempts} failed: {e}"
                )
                
                if attempt == self.retry_attempts - 1:
                    # Final attempt failed
                    logger.error(
                        f"SOAR alert failed after {self.retry_attempts} attempts: {event.event_id}"
                    )
                    return {
                        "success": False,
                        "error": str(e),
                        "attempts": self.retry_attempts,
                    }
                
                # Wait before retry (exponential backoff)
                import asyncio
                await asyncio.sleep(2 ** attempt)
        
        return {"success": False, "error": "Max retries exceeded"}
    
    def _format_payload(
        self,
        event: IDORDetectionEvent,
        auto_hold: bool,
    ) -> Dict[str, Any]:
        """
        Format detection event for SOAR platform.
        
        Each platform has different payload requirements, this method
        adapts the generic event to platform-specific format.
        """
        # Common fields across all platforms
        common = {
            "title": f"IDOR Attack Detected: {event.user_id}",
            "description": self._build_description(event),
            "severity": self._map_severity(event.severity),
            "source": "idor_detection_middleware",
            "event_id": event.event_id,
            "timestamp": event.detection_timestamp.isoformat(),
            
            # Evidence
            "user_id": event.user_id,
            "session_id": event.session_id,
            "distinct_resources": event.distinct_resources_accessed,
            "is_sequential": event.is_sequential,
            "failed_resources": event.failed_resources,
            "resource_owners": event.resource_owners,
            "time_window_seconds": event.time_window_seconds,
            
            # Telemetry snapshot
            "user_email": event.telemetry_snapshot.user_email,
            "client_ip": event.telemetry_snapshot.client_ip,
            "user_agent": event.telemetry_snapshot.user_agent,
            "request_path": event.telemetry_snapshot.request_path,
            
            # Action
            "auto_hold": auto_hold,
            
            # MITRE ATT&CK Framework
            "mitre_tactics": event.mitre_tactics,
            "mitre_techniques": event.mitre_techniques,
            "mitre_sub_techniques": event.mitre_sub_techniques or [],
            "mitre_attack_urls": [
                f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"
                for t in event.mitre_techniques
            ],
        }
        
        # Platform-specific formatting
        if self.platform == SOARPlatform.SPLUNK:
            return self._format_splunk(common, event)
        
        elif self.platform == SOARPlatform.XSOAR:
            return self._format_xsoar(common, event)
        
        elif self.platform == SOARPlatform.SERVICENOW:
            return self._format_servicenow(common, event)
        
        else:
            # Generic format
            return common
    
    def _build_description(self, event: IDORDetectionEvent) -> str:
        """Build human-readable alert description."""
        desc_parts = [
            f"IDOR enumeration attack detected against user {event.user_id}.",
            f"",
            f"Attack Pattern:",
            f"- Accessed {event.distinct_resources_accessed} distinct resources owned by other users",
            f"- Sequential access: {'YES (high confidence)' if event.is_sequential else 'NO'}",
            f"- Time window: {event.time_window_seconds} seconds",
            f"- Session: {event.session_id}",
            f"",
            f"Failed Resources:",
        ]
        
        for resource_id, owner in zip(event.failed_resources[:5], event.resource_owners[:5]):
            desc_parts.append(f"  - {resource_id} (owner: {owner})")
        
        if len(event.failed_resources) > 5:
            desc_parts.append(f"  ... and {len(event.failed_resources) - 5} more")
        
        desc_parts.extend([
            f"",
            f"Evidence:",
            f"- Request path: {event.telemetry_snapshot.request_path}",
            f"- Client IP: {event.telemetry_snapshot.client_ip or 'unknown'}",
            f"- User Agent: {event.telemetry_snapshot.user_agent or 'unknown'}",
        ])
        
        return "\n".join(desc_parts)
    
    def _map_severity(self, severity: AccessAttemptResult) -> str:
        """Map detection severity to SOAR severity levels."""
        severity_map = {
            AccessAttemptResult.CRITICAL_IDOR_ATTACK: "critical",
            AccessAttemptResult.ALERT_MEDIUM: "high",
            AccessAttemptResult.ALERT_LOW: "medium",
        }
        return severity_map.get(severity, "high")
    
    def _format_splunk(self, common: Dict, event: IDORDetectionEvent) -> Dict[str, Any]:
        """Format for Splunk SOAR (Phantom)."""
        return {
            "container": {
                "name": common["title"],
                "description": common["description"],
                "severity": common["severity"],
                "label": "security",
                "tags": ["idor", "enumeration", "ownership-violation"],
            },
            "artifacts": [
                {
                    "name": "IDOR Detection Event",
                    "cef": {
                        "sourceUserId": event.user_id,
                        "sessionId": event.session_id,
                        "requestPath": event.telemetry_snapshot.request_path,
                        "resourcesAccessed": event.distinct_resources_accessed,
                    },
                    "label": "event",
                }
            ],
        }
    
    def _format_xsoar(self, common: Dict, event: IDORDetectionEvent) -> Dict[str, Any]:
        """Format for Palo Alto Cortex XSOAR."""
        return {
            "name": common["title"],
            "type": "IDOR Enumeration",
            "severity": self._xsoar_severity(common["severity"]),
            "details": common["description"],
            "customFields": {
                "userid": event.user_id,
                "sessionid": event.session_id,
                "distinctresources": event.distinct_resources_accessed,
                "issequential": event.is_sequential,
                "autohold": common["auto_hold"],
            },
        }
    
    def _format_servicenow(self, common: Dict, event: IDORDetectionEvent) -> Dict[str, Any]:
        """Format for ServiceNow SecOps."""
        return {
            "short_description": common["title"],
            "description": common["description"],
            "urgency": self._servicenow_urgency(common["severity"]),
            "impact": "2",  # High impact (1=High, 2=Medium, 3=Low)
            "category": "Security",
            "subcategory": "Unauthorized Access",
            "u_event_id": event.event_id,
            "u_user_id": event.user_id,
            "u_session_id": event.session_id,
        }
    
    def _xsoar_severity(self, severity: str) -> int:
        """Map to XSOAR severity (0=Info, 1=Low, 2=Med, 3=High, 4=Critical)."""
        severity_map = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }
        return severity_map.get(severity, 3)
    
    def _servicenow_urgency(self, severity: str) -> str:
        """Map to ServiceNow urgency (1=High, 2=Medium, 3=Low)."""
        urgency_map = {
            "critical": "1",
            "high": "1",
            "medium": "2",
            "low": "3",
        }
        return urgency_map.get(severity, "1")
    
    async def _send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send HTTP request to SOAR webhook.
        
        Returns parsed response with incident ID.
        """
        headers = {
            "Content-Type": "application/json",
        }
        
        # Add authentication
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.webhook_url,
                json=payload,
                headers=headers,
            )
            
            # Raise for HTTP errors
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            
            # Extract incident ID (platform-specific)
            incident_id = self._extract_incident_id(result)
            
            return {
                "incident_id": incident_id,
                "response": result,
            }
    
    def _extract_incident_id(self, response: Dict[str, Any]) -> Optional[str]:
        """
        Extract incident ID from SOAR response.
        
        Different platforms return incident IDs in different fields.
        """
        # Common field names
        id_fields = [
            "id",
            "incident_id",
            "incidentId",
            "container_id",  # Splunk
            "sys_id",  # ServiceNow
            "incidentNumber",
        ]
        
        for field in id_fields:
            if field in response:
                return str(response[field])
        
        # Nested checks
        if "data" in response and "id" in response["data"]:
            return str(response["data"]["id"])
        
        return None
    
    async def test_connection(self) -> Dict[str, Any]:
        """
        Test SOAR webhook connection.
        
        Sends a test incident to verify configuration.
        
        Returns:
            dict: Test result with success status
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "SOAR webhook URL not configured"
            }
        
        test_payload = {
            "title": "SOAR Integration Test",
            "description": "Test incident from IDOR Detection Middleware",
            "severity": "low",
            "source": "idor_detection_test",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        try:
            result = await self._send_request(test_payload)
            return {
                "success": True,
                "message": "SOAR connection test successful",
                "incident_id": result.get("incident_id"),
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"SOAR connection test failed: {str(e)}"
            }


# Singleton instance
_soar_integration: Optional[SOARIntegration] = None


def get_soar_integration() -> SOARIntegration:
    """
    Get global SOAR integration singleton.
    
    Auto-configures from environment variables.
    
    Returns:
        SOARIntegration: Configured SOAR client
    """
    global _soar_integration
    
    if _soar_integration is None:
        _soar_integration = SOARIntegration()
        
        if _soar_integration.is_configured():
            logger.info(
                f"SOAR integration configured: {_soar_integration.platform.value}"
            )
        else:
            logger.warning(
                "SOAR integration not configured. "
                "Set SOAR_WEBHOOK_URL to enable."
            )
    
    return _soar_integration


async def send_idor_alert(
    event: IDORDetectionEvent,
    auto_hold: bool = True,
) -> Dict[str, Any]:
    """
    Convenience function to send IDOR alert to SOAR.
    
    Usage:
        from core.soar_integration import send_idor_alert
        
        result = await send_idor_alert(detection_event)
        if result["success"]:
            logger.info(f"Alert sent: {result['incident_id']}")
    
    Args:
        event: IDOR detection event
        auto_hold: Whether to trigger auto-hold action
    
    Returns:
        dict: Send result with success status
    """
    soar = get_soar_integration()
    return await soar.send_alert(event, auto_hold=auto_hold)
