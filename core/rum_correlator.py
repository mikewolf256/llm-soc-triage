"""
RUM (Real User Monitoring) Correlator for telemetry extraction.

Extracts frontend intent signals from HTTP request headers to enable
session-aware contextual detection.

Supported RUM Providers:
- DataDog RUM: session_id, view_id, application_id
- CloudFlare Analytics: cf-ray, pageload tracking

Purpose:
    "Stitch" frontend user behavior (RUM telemetry) with backend reality
    (authorization failures) to distinguish legitimate access from IDOR attacks.

Example Headers:
    x-datadog-session-id: d68ba5b9-7d1e-4ff5-9507-b870904cf55a
    x-datadog-view-id: 58b5b770-9d8b-4d17-9625-2f1dd1d73743
    x-datadog-application-id: 1326c560-2329-46a6-b276-f64b808e0321
    cf-ray: 7f2a1b3c4d5e6f7g-SJC
    x-user-id: user_789  # From auth middleware
"""

import re
from typing import Optional
from datetime import datetime
import logging

from fastapi import Request
from .schema.web_telemetry import (
    WebTelemetryMetadata,
    ResourceType,
    FailureType,
)


logger = logging.getLogger(__name__)


class RUMCorrelator:
    """
    Correlates RUM telemetry from multiple providers.
    
    Extracts session/user context from request headers to enable
    ownership-aware IDOR detection.
    
    Usage:
        from fastapi import Request
        from core.rum_correlator import RUMCorrelator
        
        correlator = RUMCorrelator()
        
        @app.get("/consumer/loan_applications/{loan_id}")
        async def get_loan(loan_id: str, request: Request):
            # Extract telemetry
            telemetry = correlator.extract_telemetry(
                request,
                resource_id=loan_id,
                resource_type=ResourceType.LOAN_APPLICATION
            )
            
            # Check authorization
            is_authorized = check_ownership(telemetry.user_id, loan_id)
            
            # Track for IDOR detection
            result, event = monitor.track_access_attempt(
                telemetry,
                success=is_authorized
            )
    """
    
    def __init__(self):
        """Initialize RUM correlator with header mapping."""
        # DataDog RUM header names (case-insensitive)
        self.dd_session_header = "x-datadog-session-id"
        self.dd_view_header = "x-datadog-view-id"
        self.dd_application_header = "x-datadog-application-id"
        
        # CloudFlare header names
        self.cf_ray_header = "cf-ray"
        self.cf_pageload_header = "x-pageload-id"
        
        # User context headers (from auth middleware)
        self.user_id_header = "x-user-id"
        self.user_email_header = "x-user-email"
        
        # Resource URL patterns
        self.resource_patterns = [
            # Match: /consumer/loan_applications/4395668
            (
                ResourceType.LOAN_APPLICATION,
                re.compile(r'/consumer/loan_applications/(\d+)'),
            ),
            # Match: /api/v1/loans/{loan_id}
            (
                ResourceType.LOAN_APPLICATION,
                re.compile(r'/api/v\d+/loans/([a-zA-Z0-9_-]+)'),
            ),
            # Match: /accounts/12345
            (
                ResourceType.ACCOUNT,
                re.compile(r'/accounts/([a-zA-Z0-9_-]+)'),
            ),
            # Match: /documents/doc_abc123
            (
                ResourceType.DOCUMENT,
                re.compile(r'/documents/([a-zA-Z0-9_-]+)'),
            ),
        ]
    
    def extract_telemetry(
        self,
        request: Request,
        resource_id: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        resource_owner_id: Optional[str] = None,
        failure_type: Optional[FailureType] = None,
    ) -> WebTelemetryMetadata:
        """
        Extract telemetry metadata from FastAPI request.
        
        Combines:
        1. RUM headers (DataDog, CloudFlare)
        2. User context (from auth middleware)
        3. Resource details (from URL or params)
        4. Authorization failure context
        
        Args:
            request: FastAPI Request object
            resource_id: Optional explicit resource ID (overrides URL parsing)
            resource_type: Optional explicit resource type
            resource_owner_id: Optional resource owner (from DB lookup)
            failure_type: Optional failure type (for 403 responses)
        
        Returns:
            WebTelemetryMetadata: Structured telemetry data
        
        Example:
            # Automatic extraction from headers + URL
            telemetry = correlator.extract_telemetry(request)
            
            # With explicit resource details
            telemetry = correlator.extract_telemetry(
                request,
                resource_id="loan_4395668",
                resource_type=ResourceType.LOAN_APPLICATION,
                resource_owner_id="user_456",
                failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED
            )
        """
        # Extract user context from headers (set by auth middleware)
        user_id = self._get_header(request, self.user_id_header)
        user_email = self._get_header(request, self.user_email_header)
        
        if not user_id:
            logger.warning(
                f"No user_id in request headers for {request.url.path} - "
                "IDOR detection will be impaired"
            )
            user_id = "unknown"  # Fallback for non-authenticated requests
        
        # Extract RUM headers
        dd_session_id = self._get_header(request, self.dd_session_header)
        dd_view_id = self._get_header(request, self.dd_view_header)
        dd_application_id = self._get_header(request, self.dd_application_header)
        
        cf_ray_id = self._get_header(request, self.cf_ray_header)
        cf_pageload_id = self._get_header(request, self.cf_pageload_header)
        
        # Extract resource details from URL if not provided
        if resource_id is None or resource_type is None:
            extracted_type, extracted_id = self._extract_resource_from_url(
                str(request.url.path)
            )
            resource_type = resource_type or extracted_type
            resource_id = resource_id or extracted_id
        
        # Get client context
        user_agent = self._get_header(request, "user-agent")
        client_ip = self._get_client_ip(request)
        
        # Build telemetry object
        telemetry = WebTelemetryMetadata(
            user_id=user_id,
            user_email=user_email,
            datadog_session_id=dd_session_id,
            datadog_view_id=dd_view_id,
            datadog_application_id=dd_application_id,
            cf_ray_id=cf_ray_id,
            cf_pageload_id=cf_pageload_id,
            resource_type=resource_type or ResourceType.OTHER,
            resource_id=resource_id or "unknown",
            resource_owner_id=resource_owner_id,
            http_method=request.method,
            request_path=str(request.url.path),
            failure_type=failure_type,
            failure_timestamp=datetime.utcnow(),
            user_agent=user_agent,
            client_ip=client_ip,
        )
        
        logger.debug(
            f"Extracted telemetry: user={user_id}, resource={resource_type}:"
            f"{resource_id}, session={dd_session_id or cf_ray_id}"
        )
        
        return telemetry
    
    def _get_header(self, request: Request, header_name: str) -> Optional[str]:
        """
        Get header value (case-insensitive).
        
        FastAPI headers are case-insensitive by default, but this
        provides explicit null handling.
        """
        try:
            value = request.headers.get(header_name)
            return value if value else None
        except Exception as e:
            logger.error(f"Error getting header {header_name}: {e}")
            return None
    
    def _extract_resource_from_url(
        self,
        url_path: str,
    ) -> tuple[Optional[ResourceType], Optional[str]]:
        """
        Extract resource type and ID from URL path.
        
        Tries multiple patterns to match common API path structures.
        
        Args:
            url_path: URL path (e.g., /consumer/loan_applications/4395668)
        
        Returns:
            tuple: (ResourceType, resource_id) or (None, None)
        
        Example:
            _extract_resource_from_url("/consumer/loan_applications/4395668")
            → (ResourceType.LOAN_APPLICATION, "4395668")
        """
        for resource_type, pattern in self.resource_patterns:
            match = pattern.search(url_path)
            if match:
                resource_id = match.group(1)
                logger.debug(
                    f"Matched resource pattern: type={resource_type.value}, "
                    f"id={resource_id}, path={url_path}"
                )
                return resource_type, resource_id
        
        logger.debug(f"No resource pattern matched for path: {url_path}")
        return None, None
    
    def _get_client_ip(self, request: Request) -> Optional[str]:
        """
        Get client IP address with X-Forwarded-For handling.
        
        Prioritizes X-Forwarded-For for reverse proxy scenarios.
        
        Note: This is AFTER PII scrubbing should occur. In production,
        consider hashing or truncating IPs for privacy compliance.
        """
        # Check X-Forwarded-For (reverse proxy)
        forwarded_for = self._get_header(request, "x-forwarded-for")
        if forwarded_for:
            # Take first IP in chain (original client)
            return forwarded_for.split(",")[0].strip()
        
        # Fallback to direct client
        if request.client:
            return request.client.host
        
        return None
    
    def add_resource_pattern(
        self,
        resource_type: ResourceType,
        pattern: str,
    ):
        """
        Add custom resource URL pattern for extraction.
        
        Useful for extending detection to custom API paths.
        
        Args:
            resource_type: Type of resource
            pattern: Regex pattern with one capture group for ID
        
        Example:
            correlator.add_resource_pattern(
                ResourceType.LOAN_APPLICATION,
                r'/custom/api/loans/([0-9]+)'
            )
        """
        compiled_pattern = re.compile(pattern)
        self.resource_patterns.append((resource_type, compiled_pattern))
        logger.info(
            f"Added custom resource pattern: {resource_type.value} → {pattern}"
        )
    
    def validate_telemetry(
        self,
        telemetry: WebTelemetryMetadata,
    ) -> tuple[bool, list[str]]:
        """
        Validate that telemetry has minimum required fields for IDOR detection.
        
        Args:
            telemetry: Telemetry to validate
        
        Returns:
            tuple: (is_valid, list_of_issues)
        
        Example:
            is_valid, issues = correlator.validate_telemetry(telemetry)
            if not is_valid:
                logger.warning(f"Invalid telemetry: {issues}")
        """
        issues = []
        
        # Must have user ID
        if not telemetry.user_id or telemetry.user_id == "unknown":
            issues.append("Missing user_id (required for ownership checks)")
        
        # Must have session identifier
        if not telemetry.get_session_identifier():
            issues.append(
                "Missing session identifier (datadog_session_id or cf_ray_id)"
            )
        
        # Must have resource details
        if not telemetry.resource_id or telemetry.resource_id == "unknown":
            issues.append("Missing resource_id (cannot track access)")
        
        if telemetry.resource_type == ResourceType.OTHER:
            issues.append("Unknown resource_type (pattern matching failed)")
        
        is_valid = len(issues) == 0
        
        if not is_valid:
            logger.warning(
                f"Telemetry validation failed: {', '.join(issues)}"
            )
        
        return is_valid, issues
