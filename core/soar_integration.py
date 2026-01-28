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
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum

from .schema.web_telemetry import IDORDetectionEvent, AccessAttemptResult
from .telemetry_scrubber import scrub_event_for_soar
from .schema.chronicle_events import ChronicleCaseRequest, ChronicleUDMAnnotation, ChronicleSeverity


logger = logging.getLogger(__name__)


class SOARPlatform(str, Enum):
    """Supported SOAR platforms"""
    GENERIC = "generic"  # Generic webhook
    SPLUNK = "splunk"  # Splunk SOAR (Phantom)
    XSOAR = "xsoar"  # Palo Alto Cortex XSOAR
    RESILIENT = "resilient"  # IBM Resilient
    SERVICENOW = "servicenow"  # ServiceNow SecOps
    CHRONICLE = "chronicle"  # Google Chronicle SOAR


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
        
        # Chronicle integration (lazy loaded)
        self.chronicle_client = None
        self.chronicle_enabled = os.getenv("CHRONICLE_SOAR_INTEGRATION", "false").lower() == "true"
        
        if self.chronicle_enabled:
            try:
                from .chronicle_integration import get_chronicle_client
                self.chronicle_client = get_chronicle_client()
                if self.chronicle_client.is_configured():
                    logger.info("Chronicle SOAR integration enabled")
                else:
                    logger.warning("Chronicle SOAR enabled but not configured")
                    self.chronicle_enabled = False
            except Exception as e:
                logger.warning(f"Chronicle SOAR initialization failed: {e}")
                self.chronicle_enabled = False
        
        if not self.webhook_url and not self.chronicle_enabled:
            logger.warning(
                "SOAR integration not configured. "
                "Set SOAR_WEBHOOK_URL or enable Chronicle SOAR."
            )
    
    def is_configured(self) -> bool:
        """Check if SOAR integration is properly configured."""
        return bool(self.webhook_url or self.chronicle_enabled)
    
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


    async def send_to_chronicle(
        self,
        event: IDORDetectionEvent,
        create_case: bool = True,
        annotate_udm: bool = True,
    ) -> Dict[str, Any]:
        """
        Send detection to Chronicle SOAR with PII scrubbing options.
        
        Security:
            - Case data: PII scrubbing configurable via SCRUB_PII_FOR_CHRONICLE
            - UDM annotations: ALWAYS PII-scrubbed (long-term storage compliance)
        
        Args:
            event: IDOR detection event
            create_case: Create Chronicle case
            annotate_udm: Annotate original UDM events
        
        Returns:
            dict: Send result with case_id and annotation_id
        """
        if not self.chronicle_enabled or not self.chronicle_client:
            logger.warning("Chronicle SOAR not configured")
            return {"success": False, "error": "Chronicle not configured"}
        
        results = {}
        
        try:
            # Create Chronicle case (PII scrubbing configurable)
            if create_case:
                logger.info(f"Creating Chronicle case for event: {event.event_id}")
                
                case_request = ChronicleCaseRequest(
                    title=f"IDOR Attack Detected: {event.severity.value}",
                    description=f"Identity-Asset Monitor detected IDOR enumeration attack.\n\n"
                               f"User: {event.telemetry_snapshot.user_id}\n"
                               f"Session: {event.telemetry_snapshot.get_session_identifier()}\n"
                               f"Distinct Resources: {event.distinct_resources_accessed}\n"
                               f"Time Window: {event.time_window_seconds}s\n\n"
                               f"Failed Resources: {', '.join(event.failed_resources)}\n"
                               f"Resource Owners: {', '.join(event.resource_owners)}\n\n"
                               f"Detection Logic: {event.is_sequential and 'Sequential' or 'Non-sequential'} "
                               f"access pattern detected.",
                    severity=ChronicleSeverity[event.severity.value],
                    alert_id=event.event_id,
                    detection_timestamp=event.detection_timestamp,
                    iocs=[],  # IOCs not applicable for IDOR
                    affected_assets=[],
                    affected_users=[event.telemetry_snapshot.user_id],
                    ai_reasoning=f"Ownership-aware IDOR detection: {event.distinct_resources_accessed} "
                                f"unauthorized access attempts to other users' resources.",
                    confidence_score=0.95 if event.is_sequential else 0.80,
                    mitre_tactics=event.mitre_tactics,
                    mitre_techniques=event.mitre_techniques,
                    assigned_to="soc_tier2",
                    priority="high" if event.severity.value == "CRITICAL_IDOR_ATTACK" else "medium",
                )
                
                # PII scrubbing for case: optional (configurable)
                scrub_case = os.getenv("SCRUB_PII_FOR_CHRONICLE", "false").lower() == "true"
                case_result = await self.chronicle_client.create_case(
                    case_request,
                    scrub_pii=scrub_case
                )
                
                results["case_created"] = case_result.get("success", False)
                results["case_id"] = case_result.get("case_id")
                results["case_url"] = case_result.get("case_url")
            
            # Annotate UDM events (ALWAYS PII-scrubbed)
            if annotate_udm and hasattr(event, 'raw_udm_event_ids'):
                logger.info(f"Annotating UDM events for: {event.event_id}")
                
                # Create annotation for each UDM event
                for udm_event_id in event.raw_udm_event_ids[:5]:  # Limit to 5
                    annotation = ChronicleUDMAnnotation(
                        event_id=udm_event_id,
                        event_timestamp=event.detection_timestamp,
                        annotation_type="ai_idor_detection",
                        annotation_text=f"IDOR Attack Detected (AI Confidence: 95%): "
                                      f"User attempted unauthorized access to {event.distinct_resources_accessed} "
                                      f"resources owned by other users. "
                                      f"Pattern: {event.is_sequential and 'Sequential' or 'Non-sequential'}. "
                                      f"MITRE: {', '.join(event.mitre_techniques)}.",
                        triage_result=event.severity.value,
                        confidence=0.95 if event.is_sequential else 0.80,
                        severity_override=ChronicleSeverity[event.severity.value],
                        tags=["idor_attack", "ownership_violation", "automated_detection"],
                        mitre_tactics=event.mitre_tactics,
                        mitre_techniques=event.mitre_techniques,
                        annotated_by="llm-soc-triage-idor-monitor",
                    )
                    
                    # UDM annotations: ALWAYS scrubbed (non-configurable)
                    annotation_result = await self.chronicle_client.annotate_udm_event(annotation)
                    
                    if annotation_result.get("success"):
                        results["udm_annotations"] = results.get("udm_annotations", [])
                        results["udm_annotations"].append(annotation_result.get("annotation_id"))
            
            results["success"] = results.get("case_created", False) or bool(results.get("udm_annotations"))
            
            logger.info(f"Chronicle SOAR submission complete: {event.event_id}")
            return results
        
        except Exception as e:
            logger.error(f"Chronicle SOAR submission failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def send_alert(
        self,
        event: IDORDetectionEvent,
        auto_hold: bool = True,
        scrub_pii_for_soar: Optional[bool] = None,
        send_to_chronicle: bool = None,
    ) -> Dict[str, Any]:
        """
        Send IDOR detection alert to SOAR with Chronicle support.
        
        Enhanced to support both webhook-based SOAR and Chronicle SOAR.
        
        Args:
            event: IDOR detection event
            auto_hold: Whether to trigger auto-hold action
            scrub_pii_for_soar: Override default PII scrubbing for webhook SOAR
            send_to_chronicle: Send to Chronicle SOAR (default: check env)
        
        Returns:
            dict: Send result with incident_id or case_id
        """
        results = {}
        
        # Send to webhook SOAR (existing)
        if self.webhook_url:
            webhook_result = await self._send_webhook(event, auto_hold, scrub_pii_for_soar)
            results["webhook"] = webhook_result
        
        # Send to Chronicle SOAR (new)
        _send_chronicle = send_to_chronicle if send_to_chronicle is not None \
                         else self.chronicle_enabled
        
        if _send_chronicle:
            chronicle_result = await self.send_to_chronicle(
                event,
                create_case=True,
                annotate_udm=os.getenv("CHRONICLE_UDM_ANNOTATIONS", "true").lower() == "true"
            )
            results["chronicle"] = chronicle_result
        
        # Aggregate success
        results["success"] = any(
            r.get("success", False) 
            for r in [results.get("webhook"), results.get("chronicle")] 
            if r
        )
        
        return results
    
    async def _send_webhook(
        self,
        event: IDORDetectionEvent,
        auto_hold: bool = True,
        scrub_pii_for_soar: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Original webhook-based SOAR send (extracted for clarity)."""
        if not self.is_configured():
            logger.warning("SOAR webhook not configured, skipping alert")
            return {"success": False, "error": "SOAR not configured"}
        
        # Check if PII scrubbing is enabled
        _scrub = scrub_pii_for_soar if scrub_pii_for_soar is not None \
                 else os.getenv("SCRUB_PII_FOR_SOAR", "false").lower() == "true"
        
        if _scrub:
            logger.info(f"Scrubbing PII from event {event.event_id} before SOAR transmission")
            event = scrub_event_for_soar(event)
        
        # Format payload for platform
        payload = self._format_payload(event, auto_hold)
        
        # Send with retry logic
        attempt = 0
        last_error = None
        
        while attempt < self.retry_attempts:
            try:
                attempt += 1
                logger.info(
                    f"Sending IDOR alert to SOAR: {event.event_id} "
                    f"(attempt {attempt}/{self.retry_attempts})"
                )
                
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        self.webhook_url,
                        json=payload,
                        headers=self._get_headers(),
                    )
                    response.raise_for_status()
                
                result = response.json() if response.content else {}
                incident_id = result.get("incident_id") or result.get("id") or event.event_id
                
                logger.info(f"SOAR alert sent successfully: {incident_id}")
                
                return {
                    "success": True,
                    "incident_id": incident_id,
                    "platform": self.platform.value,
                    "attempt": attempt,
                }
            
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"SOAR alert attempt {attempt} failed: {last_error}"
                )
                
                if attempt < self.retry_attempts:
                    # Exponential backoff
                    await asyncio.sleep(2 ** attempt)
        
        # All retries failed
        logger.error(
            f"SOAR alert failed after {self.retry_attempts} attempts: "
            f"{last_error}"
        )
        
        return {
            "success": False,
            "error": last_error,
            "attempts": self.retry_attempts,
        }


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
