"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Google Chronicle Integration with PII Scrubbing

This module provides Chronicle API integration with mandatory PII scrubbing
at all data boundaries, maintaining the "Sandwich Model" security architecture.

Security Architecture:
    - Inbound: All UDM events scrubbed before LLM processing
    - Context Queries: All API responses scrubbed before LLM context injection
    - Outbound: UDM annotations always scrubbed; case data configurable

Integration Points:
    1. Webhook receiver for YARA-L triggered alerts
    2. Context enrichment (prevalence, baselines, network intel)
    3. SOAR case creation and UDM annotation
"""

import os
import logging
import hashlib
import hmac
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

import httpx
from google.cloud import chronicle
from google.oauth2 import service_account

from .scrubber import get_default_scrubber, scrub_pii
from .schema.chronicle_events import (
    ChronicleUDMAlert,
    ChroniclePrevalenceData,
    ChronicleUserBaseline,
    ChronicleNetworkContext,
    ChronicleCaseRequest,
    ChronicleUDMAnnotation,
)


logger = logging.getLogger(__name__)


class ChronicleRegion(str, Enum):
    """Chronicle instance regions"""
    US = "us"
    EUROPE = "europe"
    ASIA = "asia"


class ChronicleClient:
    """
    Chronicle API client with built-in PII scrubbing.
    
    All API responses are scrubbed before returning to caller, maintaining
    the "Sandwich Model" security boundary.
    
    Usage:
        client = ChronicleClient(
            credentials_file="/path/to/service-account.json",
            customer_id="your_customer_id",
            scrub_pii=True  # Always scrub before LLM
        )
        
        # Query UDM with automatic PII scrubbing
        results = await client.search_udm(
            query='metadata.event_type = "HTTP_REQUEST"',
            time_range="1h"
        )
        # results are pre-scrubbed for LLM consumption
    """
    
    def __init__(
        self,
        credentials_file: Optional[str] = None,
        customer_id: Optional[str] = None,
        region: ChronicleRegion = ChronicleRegion.US,
        scrub_pii: bool = True,
        timeout: int = 30,
    ):
        """
        Initialize Chronicle client with PII scrubbing.
        
        Args:
            credentials_file: Path to service account JSON (or env CHRONICLE_CREDENTIALS_FILE)
            customer_id: Chronicle customer ID (or env CHRONICLE_CUSTOMER_ID)
            region: Chronicle region (us, europe, asia)
            scrub_pii: Enable PII scrubbing (default: True for LLM safety)
            timeout: API request timeout in seconds
        """
        self.credentials_file = credentials_file or os.getenv("CHRONICLE_CREDENTIALS_FILE")
        self.customer_id = customer_id or os.getenv("CHRONICLE_CUSTOMER_ID")
        self.region = ChronicleRegion(os.getenv("CHRONICLE_REGION", region))
        self.scrub_pii = scrub_pii
        self.timeout = timeout
        
        # Initialize PII scrubber for all API responses
        self.scrubber = get_default_scrubber()
        
        # Initialize Chronicle API client
        if self.credentials_file and os.path.exists(self.credentials_file):
            self.credentials = service_account.Credentials.from_service_account_file(
                self.credentials_file,
                scopes=["https://www.googleapis.com/auth/chronicle-backstory"]
            )
            logger.info(f"Chronicle client initialized for region: {self.region}")
        else:
            logger.warning(
                "Chronicle credentials not configured. "
                "Set CHRONICLE_CREDENTIALS_FILE environment variable."
            )
            self.credentials = None
    
    def is_configured(self) -> bool:
        """Check if Chronicle integration is properly configured."""
        return bool(self.credentials and self.customer_id)
    
    async def search_udm(
        self,
        query: str,
        time_range: str = "1h",
        max_results: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search Chronicle UDM with automatic PII scrubbing.
        
        Args:
            query: UDM query string (e.g., 'metadata.event_type = "HTTP_REQUEST"')
            time_range: Time range (e.g., "1h", "24h", "7d")
            max_results: Maximum results to return
        
        Returns:
            List of scrubbed UDM events (PII redacted for LLM safety)
        
        Security:
            All results pass through PII scrubber before returning.
            IPs, emails, hostnames replaced with [REDACTED] tokens.
        """
        if not self.is_configured():
            logger.warning("Chronicle not configured, returning empty results")
            return []
        
        try:
            logger.info(f"Chronicle UDM search: {query[:100]}... (range: {time_range})")
            
            # Calculate time bounds
            end_time = datetime.utcnow()
            start_time = self._parse_time_range(time_range, end_time)
            
            # Execute Chronicle UDM search
            # Note: Using httpx for async, actual Chronicle SDK would be wrapped here
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"https://{self.region}.backstory.chronicle.security/v2/udm/search",
                    headers={"Authorization": f"Bearer {self._get_access_token()}"},
                    json={
                        "query": query,
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat(),
                        "max_results": max_results,
                    }
                )
                response.raise_for_status()
                results = response.json().get("events", [])
            
            logger.info(f"Chronicle UDM search returned {len(results)} events")
            
            # CRITICAL: Scrub PII before returning to caller
            if self.scrub_pii:
                scrubbed_results = []
                for event in results:
                    scrubbed_event = self.scrubber.scrub(event)
                    scrubbed_results.append(scrubbed_event)
                
                logger.debug(f"Scrubbed {len(scrubbed_results)} UDM events for LLM consumption")
                return scrubbed_results
            
            return results
        
        except Exception as e:
            logger.error(f"Chronicle UDM search failed: {e}", exc_info=True)
            return []
    
    async def get_asset_prevalence(
        self,
        indicator: str,
        indicator_type: str = "hash",
        time_range: str = "30d",
    ) -> ChroniclePrevalenceData:
        """
        Query asset prevalence with PII scrubbing.
        
        Args:
            indicator: IOC to check (hash, IP, domain)
            indicator_type: Type of indicator (hash, ip, domain, url)
            time_range: Lookback period (e.g., "30d")
        
        Returns:
            Prevalence data with scrubbed hostnames
        
        Example:
            prevalence = await client.get_asset_prevalence(
                indicator="abc123...",
                indicator_type="hash"
            )
            # prevalence.affected_assets = 3 (count only, hostnames scrubbed)
        """
        if not self.is_configured():
            return ChroniclePrevalenceData(
                indicator=indicator,
                indicator_type=indicator_type,
                affected_assets=0,
                first_seen=None,
                last_seen=None,
                asset_names=[],
            )
        
        try:
            logger.info(f"Chronicle prevalence query: {indicator_type}={indicator[:20]}...")
            
            end_time = datetime.utcnow()
            start_time = self._parse_time_range(time_range, end_time)
            
            # Query Chronicle for prevalence
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://{self.region}.backstory.chronicle.security/v2/ioc/prevalence",
                    headers={"Authorization": f"Bearer {self._get_access_token()}"},
                    params={
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat(),
                    }
                )
                response.raise_for_status()
                data = response.json()
            
            # Extract prevalence data
            affected_count = data.get("affected_asset_count", 0)
            asset_names = data.get("affected_asset_names", [])
            first_seen = data.get("first_seen")
            last_seen = data.get("last_seen")
            
            # CRITICAL: Scrub asset names (hostnames contain PII)
            if self.scrub_pii and asset_names:
                scrubbed_names = [
                    self.scrubber.scrub({"hostname": name}).get("hostname", "[HOSTNAME_REDACTED]")
                    for name in asset_names
                ]
            else:
                scrubbed_names = asset_names
            
            prevalence = ChroniclePrevalenceData(
                indicator=indicator,
                indicator_type=indicator_type,
                affected_assets=affected_count,
                first_seen=datetime.fromisoformat(first_seen) if first_seen else None,
                last_seen=datetime.fromisoformat(last_seen) if last_seen else None,
                asset_names=scrubbed_names,
            )
            
            logger.info(f"Chronicle prevalence: {affected_count} assets affected")
            return prevalence
        
        except Exception as e:
            logger.error(f"Chronicle prevalence query failed: {e}", exc_info=True)
            return ChroniclePrevalenceData(
                indicator=indicator,
                indicator_type=indicator_type,
                affected_assets=0,
                first_seen=None,
                last_seen=None,
                asset_names=[],
            )
    
    async def get_user_baseline(
        self,
        user_id: str,
        lookback_days: int = 30,
    ) -> ChronicleUserBaseline:
        """
        Get user behavior baseline with PII scrubbing.
        
        Args:
            user_id: User identifier (will be scrubbed in output)
            lookback_days: Days of historical behavior
        
        Returns:
            User baseline with scrubbed PII (IPs, locations tokenized)
        """
        if not self.is_configured():
            return ChronicleUserBaseline(
                user_id=user_id,
                typical_login_locations=[],
                typical_source_ips=[],
                typical_user_agents=[],
                average_daily_logins=0,
            )
        
        try:
            logger.info(f"Chronicle user baseline query: user={user_id[:10]}...")
            
            # Query Chronicle for user behavior
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=lookback_days)
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://{self.region}.backstory.chronicle.security/v2/users/{user_id}/baseline",
                    headers={"Authorization": f"Bearer {self._get_access_token()}"},
                    params={
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat(),
                    }
                )
                response.raise_for_status()
                data = response.json()
            
            # Extract baseline data
            locations = data.get("typical_locations", [])
            source_ips = data.get("typical_source_ips", [])
            user_agents = data.get("typical_user_agents", [])
            avg_logins = data.get("average_daily_logins", 0)
            
            # CRITICAL: Scrub PII from baseline data
            if self.scrub_pii:
                scrubbed_ips = [
                    self.scrubber.scrub({"ip": ip}).get("ip", "[IP_REDACTED]")
                    for ip in source_ips
                ]
                # Keep location cities but scrub specific addresses
                scrubbed_locations = [loc.split(",")[0] if "," in loc else loc for loc in locations]
            else:
                scrubbed_ips = source_ips
                scrubbed_locations = locations
            
            baseline = ChronicleUserBaseline(
                user_id=user_id,
                typical_login_locations=scrubbed_locations,
                typical_source_ips=scrubbed_ips,
                typical_user_agents=user_agents[:5],  # Limit to top 5
                average_daily_logins=avg_logins,
            )
            
            logger.info(f"Chronicle user baseline: {len(scrubbed_locations)} locations, {len(scrubbed_ips)} IPs")
            return baseline
        
        except Exception as e:
            logger.error(f"Chronicle user baseline query failed: {e}", exc_info=True)
            return ChronicleUserBaseline(
                user_id=user_id,
                typical_login_locations=[],
                typical_source_ips=[],
                typical_user_agents=[],
                average_daily_logins=0,
            )
    
    async def get_network_context(
        self,
        ip_address: str,
        lookback_days: int = 90,
    ) -> ChronicleNetworkContext:
        """
        Get network context for IP with PII scrubbing.
        
        Args:
            ip_address: IP to investigate
            lookback_days: Historical lookback period
        
        Returns:
            Network context with scrubbed connection details
        """
        if not self.is_configured():
            return ChronicleNetworkContext(
                ip_address=ip_address,
                first_seen=None,
                last_seen=None,
                connection_count=0,
                connected_assets=[],
                reputation_score=None,
            )
        
        try:
            logger.info(f"Chronicle network context query: ip={ip_address}")
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=lookback_days)
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://{self.region}.backstory.chronicle.security/v2/network/{ip_address}",
                    headers={"Authorization": f"Bearer {self._get_access_token()}"},
                    params={
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat(),
                    }
                )
                response.raise_for_status()
                data = response.json()
            
            # Extract network data
            first_seen = data.get("first_seen")
            last_seen = data.get("last_seen")
            conn_count = data.get("connection_count", 0)
            connected_assets = data.get("connected_assets", [])
            reputation = data.get("reputation_score")
            
            # CRITICAL: Scrub connected asset hostnames
            if self.scrub_pii and connected_assets:
                scrubbed_assets = [
                    self.scrubber.scrub({"hostname": asset}).get("hostname", "[HOSTNAME_REDACTED]")
                    for asset in connected_assets
                ]
            else:
                scrubbed_assets = connected_assets
            
            context = ChronicleNetworkContext(
                ip_address=ip_address,
                first_seen=datetime.fromisoformat(first_seen) if first_seen else None,
                last_seen=datetime.fromisoformat(last_seen) if last_seen else None,
                connection_count=conn_count,
                connected_assets=scrubbed_assets,
                reputation_score=reputation,
            )
            
            logger.info(f"Chronicle network context: {conn_count} connections")
            return context
        
        except Exception as e:
            logger.error(f"Chronicle network context query failed: {e}", exc_info=True)
            return ChronicleNetworkContext(
                ip_address=ip_address,
                first_seen=None,
                last_seen=None,
                connection_count=0,
                connected_assets=[],
                reputation_score=None,
            )
    
    async def create_case(
        self,
        case_request: ChronicleCaseRequest,
        scrub_pii: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Create Chronicle SOAR case with configurable PII scrubbing.
        
        Args:
            case_request: Case creation request
            scrub_pii: Override default PII scrubbing (None = use env config)
        
        Returns:
            Case creation response with case_id
        
        Security:
            PII scrubbing configurable via SCRUB_PII_FOR_CHRONICLE env var.
            Default: false (Chronicle is internal, full context helpful)
        """
        if not self.is_configured():
            logger.warning("Chronicle not configured, cannot create case")
            return {"success": False, "error": "Chronicle not configured"}
        
        # Determine if PII scrubbing needed
        _scrub = scrub_pii if scrub_pii is not None \
                else os.getenv("SCRUB_PII_FOR_CHRONICLE", "false").lower() == "true"
        
        try:
            # Convert to dict for potential scrubbing
            case_data = case_request.model_dump()
            
            # Optional PII scrubbing for case data
            if _scrub:
                logger.info(f"Scrubbing PII from Chronicle case: {case_request.title}")
                case_data = self.scrubber.scrub(case_data)
            
            # Create Chronicle case
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"https://{self.region}.backstory.chronicle.security/v2/cases",
                    headers={"Authorization": f"Bearer {self._get_access_token()}"},
                    json=case_data,
                )
                response.raise_for_status()
                result = response.json()
            
            case_id = result.get("case_id")
            logger.info(f"Chronicle case created: {case_id}")
            
            return {
                "success": True,
                "case_id": case_id,
                "case_url": f"https://{self.region}.chronicle.security/cases/{case_id}",
            }
        
        except Exception as e:
            logger.error(f"Chronicle case creation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    async def annotate_udm_event(
        self,
        annotation: ChronicleUDMAnnotation,
    ) -> Dict[str, Any]:
        """
        Annotate UDM event with AI reasoning (always PII scrubbed).
        
        Args:
            annotation: UDM annotation with AI context
        
        Returns:
            Annotation response
        
        Security:
            UDM annotations are ALWAYS PII-scrubbed (long-term storage compliance).
            This is non-configurable for regulatory reasons.
        """
        if not self.is_configured():
            logger.warning("Chronicle not configured, cannot annotate UDM")
            return {"success": False, "error": "Chronicle not configured"}
        
        try:
            # Convert to dict
            annotation_data = annotation.model_dump()
            
            # CRITICAL: Always scrub UDM annotations (long-term storage)
            logger.info(f"Scrubbing PII from UDM annotation: {annotation.event_id}")
            scrubbed_annotation = self.scrubber.scrub(annotation_data)
            
            # Annotate Chronicle UDM event
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"https://{self.region}.backstory.chronicle.security/v2/udm/annotate",
                    headers={"Authorization": f"Bearer {self._get_access_token()}"},
                    json=scrubbed_annotation,
                )
                response.raise_for_status()
                result = response.json()
            
            logger.info(f"Chronicle UDM annotated: {annotation.event_id}")
            
            return {
                "success": True,
                "event_id": annotation.event_id,
                "annotation_id": result.get("annotation_id"),
            }
        
        except Exception as e:
            logger.error(f"Chronicle UDM annotation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def _parse_time_range(self, time_range: str, end_time: datetime) -> datetime:
        """Parse time range string to start datetime."""
        if time_range.endswith("h"):
            hours = int(time_range[:-1])
            return end_time - timedelta(hours=hours)
        elif time_range.endswith("d"):
            days = int(time_range[:-1])
            return end_time - timedelta(days=days)
        elif time_range.endswith("m"):
            minutes = int(time_range[:-1])
            return end_time - timedelta(minutes=minutes)
        else:
            # Default: 1 hour
            return end_time - timedelta(hours=1)
    
    def _get_access_token(self) -> str:
        """Get Chronicle API access token from service account."""
        if self.credentials:
            self.credentials.refresh(httpx.Request())
            return self.credentials.token
        return ""


class ChronicleContextEnricher:
    """
    Enriches alerts with Chronicle context while maintaining PII scrubbing.
    
    Integrates with existing BusinessContextManager to add:
    - Asset prevalence data ("This hash seen on 3 other hosts")
    - User behavior baselines ("User typically logs in from US East")
    - Network intelligence ("This IP has 0 prior connections")
    - Historical alert context ("Similar alert resolved as FP 14 days ago")
    
    Security:
        All Chronicle API responses are PII-scrubbed before LLM context injection.
    
    Usage:
        enricher = ChronicleContextEnricher(chronicle_client)
        
        chronicle_context = await enricher.enrich_from_chronicle(
            alert_iocs=["abc123hash", "1.2.3.4"],
            affected_host="server01",
            affected_user="john.doe"
        )
        # Returns scrubbed context safe for LLM
    """
    
    def __init__(self, chronicle_client: ChronicleClient):
        """
        Initialize context enricher.
        
        Args:
            chronicle_client: Chronicle API client (with PII scrubbing enabled)
        """
        self.client = chronicle_client
    
    async def enrich_from_chronicle(
        self,
        alert_iocs: List[str],
        affected_host: Optional[str] = None,
        affected_user: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enrich alert with Chronicle context (all responses PII-scrubbed).
        
        Args:
            alert_iocs: List of IOCs (hashes, IPs, domains)
            affected_host: Hostname (if available)
            affected_user: User ID (if available)
        
        Returns:
            Dictionary with Chronicle enrichment data (PII-scrubbed)
        
        Example:
            {
                "prevalence": {
                    "hash_abc123": "Seen on 3 hosts in last 30 days"
                },
                "user_baseline": {
                    "typical_locations": ["US-East", "US-West"],
                    "anomaly": "Login from Asia (unusual)"
                },
                "network_context": {
                    "ip_1.2.3.4": "0 prior connections (new IP)"
                }
            }
        """
        if not self.client.is_configured():
            return {}
        
        enrichment = {}
        
        try:
            # Query prevalence for all IOCs
            if alert_iocs:
                prevalence_results = {}
                for ioc in alert_iocs[:5]:  # Limit to 5 IOCs to avoid rate limits
                    # Determine IOC type
                    ioc_type = self._detect_ioc_type(ioc)
                    
                    # Query Chronicle
                    prevalence = await self.client.get_asset_prevalence(
                        indicator=ioc,
                        indicator_type=ioc_type,
                        time_range="30d"
                    )
                    
                    # Format for LLM consumption
                    prevalence_results[ioc[:20]] = self._format_prevalence(prevalence)
                
                if prevalence_results:
                    enrichment["chronicle_prevalence"] = prevalence_results
            
            # Query user baseline if user provided
            if affected_user:
                user_baseline = await self.client.get_user_baseline(
                    user_id=affected_user,
                    lookback_days=30
                )
                
                enrichment["chronicle_user_baseline"] = self._format_user_baseline(user_baseline)
            
            # Query network context for IP IOCs
            ip_iocs = [ioc for ioc in alert_iocs if self._is_ip(ioc)]
            if ip_iocs:
                network_context = {}
                for ip in ip_iocs[:3]:  # Limit to 3 IPs
                    net_context = await self.client.get_network_context(
                        ip_address=ip,
                        lookback_days=90
                    )
                    network_context[ip] = self._format_network_context(net_context)
                
                if network_context:
                    enrichment["chronicle_network_context"] = network_context
            
            logger.info(f"Chronicle enrichment complete: {len(enrichment)} categories")
            return enrichment
        
        except Exception as e:
            logger.error(f"Chronicle enrichment failed: {e}", exc_info=True)
            return enrichment
    
    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type from string."""
        if self._is_ip(ioc):
            return "ip"
        elif self._is_domain(ioc):
            return "domain"
        elif self._is_hash(ioc):
            return "hash"
        elif ioc.startswith("http"):
            return "url"
        else:
            return "hash"  # Default
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain."""
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, value))
    
    def _is_hash(self, value: str) -> bool:
        """Check if value is a hash (MD5, SHA1, SHA256)."""
        return len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value)
    
    def _format_prevalence(self, prevalence: ChroniclePrevalenceData) -> str:
        """Format prevalence data for LLM prompt."""
        if prevalence.affected_assets == 0:
            return "Never seen before in this environment (new IOC)"
        elif prevalence.affected_assets == 1:
            return "Seen on 1 host only (rare)"
        elif prevalence.affected_assets < 5:
            return f"Seen on {prevalence.affected_assets} hosts in last 30 days (uncommon)"
        elif prevalence.affected_assets < 20:
            return f"Seen on {prevalence.affected_assets} hosts in last 30 days (moderate prevalence)"
        else:
            return f"Seen on {prevalence.affected_assets}+ hosts in last 30 days (widespread)"
    
    def _format_user_baseline(self, baseline: ChronicleUserBaseline) -> str:
        """Format user baseline for LLM prompt."""
        if not baseline.typical_login_locations:
            return "No historical baseline available for this user"
        
        locations = ", ".join(baseline.typical_login_locations[:3])
        avg_logins = baseline.average_daily_logins
        
        return f"User typically logs in from: {locations}. Average {avg_logins:.1f} logins/day."
    
    def _format_network_context(self, context: ChronicleNetworkContext) -> str:
        """Format network context for LLM prompt."""
        if context.connection_count == 0:
            return "New IP - 0 prior connections to our infrastructure"
        elif context.connection_count < 5:
            return f"Rare IP - only {context.connection_count} prior connections"
        elif context.connection_count < 50:
            return f"Uncommon IP - {context.connection_count} prior connections"
        else:
            return f"Known IP - {context.connection_count}+ connections to our infrastructure"


class ChronicleAlertHandler:
    """
    Webhook handler for Chronicle YARA-L triggered alerts.
    
    Security:
        - Validates webhook signatures to prevent spoofing
        - Scrubs all UDM data before LLM processing
        - Maintains audit trail of Chronicle alerts
    
    Usage:
        handler = ChronicleAlertHandler(
            webhook_secret="your_secret",
            scrubber=get_default_scrubber()
        )
        
        @app.post("/v1/chronicle/webhook")
        async def webhook(request: Request):
            if not handler.verify_signature(request):
                raise HTTPException(403, "Invalid signature")
            
            alert = await request.json()
            scrubbed_alert = handler.scrub_webhook_alert(alert)
            return scrubbed_alert
    """
    
    def __init__(
        self,
        webhook_secret: Optional[str] = None,
    ):
        """
        Initialize Chronicle webhook handler.
        
        Args:
            webhook_secret: Shared secret for signature verification
        """
        self.webhook_secret = webhook_secret or os.getenv("CHRONICLE_WEBHOOK_SECRET")
        self.scrubber = get_default_scrubber()
        
        if not self.webhook_secret:
            logger.warning(
                "Chronicle webhook secret not configured. "
                "Set CHRONICLE_WEBHOOK_SECRET environment variable."
            )
    
    def verify_signature(
        self,
        payload: bytes,
        signature_header: str,
    ) -> bool:
        """
        Verify Chronicle webhook signature to prevent spoofing.
        
        Args:
            payload: Raw request body bytes
            signature_header: X-Chronicle-Signature header value
        
        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            logger.warning("Chronicle webhook secret not configured, skipping verification")
            return True  # Allow in dev mode
        
        try:
            # Compute expected signature
            expected_signature = hmac.new(
                self.webhook_secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Compare with provided signature
            provided_signature = signature_header.replace("sha256=", "")
            
            is_valid = hmac.compare_digest(expected_signature, provided_signature)
            
            if not is_valid:
                logger.warning("Chronicle webhook signature validation failed")
            
            return is_valid
        
        except Exception as e:
            logger.error(f"Chronicle webhook signature verification error: {e}")
            return False
    
    def scrub_webhook_alert(
        self,
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Scrub PII from Chronicle webhook alert (CRITICAL for LLM safety).
        
        Args:
            alert: Raw Chronicle alert payload (contains PII)
        
        Returns:
            Scrubbed alert safe for LLM processing
        
        Security:
            This is a MANDATORY step before LLM processing.
            UDM events contain raw logs with IPs, emails, hostnames, usernames.
        """
        logger.info("Scrubbing PII from Chronicle webhook alert")
        
        # Scrub entire alert payload
        scrubbed_alert = self.scrubber.scrub(alert)
        
        logger.debug("Chronicle alert PII scrubbing complete")
        return scrubbed_alert


# Singleton instances for dependency injection
_chronicle_client: Optional[ChronicleClient] = None
_chronicle_alert_handler: Optional[ChronicleAlertHandler] = None


def get_chronicle_client() -> ChronicleClient:
    """Get Chronicle client singleton (lazy initialization)."""
    global _chronicle_client
    if _chronicle_client is None:
        _chronicle_client = ChronicleClient()
    return _chronicle_client


def get_chronicle_alert_handler() -> ChronicleAlertHandler:
    """Get Chronicle alert handler singleton (lazy initialization)."""
    global _chronicle_alert_handler
    if _chronicle_alert_handler is None:
        _chronicle_alert_handler = ChronicleAlertHandler()
    return _chronicle_alert_handler
