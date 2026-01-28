"""
Pydantic models for web application telemetry and ownership tracking.

This schema captures frontend RUM (Real User Monitoring) data from DataDog
and CloudFlare analytics, correlated with backend authorization events.

Used for Session-Aware IDOR Detection - distinguishing legitimate access
to owned resources from enumeration attacks on other users' data.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class ResourceType(str, Enum):
    """Types of resources that can be accessed"""
    LOAN_APPLICATION = "loan_application"
    ACCOUNT = "account"
    DOCUMENT = "document"
    PAYMENT = "payment"
    USER_PROFILE = "user_profile"
    OTHER = "other"


class FailureType(str, Enum):
    """Types of authorization failures"""
    AUTHZ_OWNERSHIP_DENIED = "authz_ownership_denied"  # User doesn't own resource
    AUTHZ_PERMISSION_DENIED = "authz_permission_denied"  # Insufficient permissions
    AUTHZ_NOT_FOUND = "authz_not_found"  # Resource doesn't exist
    AUTHZ_EXPIRED = "authz_expired"  # Session/token expired
    AUTHZ_SUSPENDED = "authz_suspended"  # Account suspended
    OTHER = "other"


class WebTelemetryMetadata(BaseModel):
    """
    Frontend telemetry from RUM providers with ownership tracking.
    
    This schema captures the "Frontend Intent" - what the user is trying
    to do based on their session and the resource they're requesting.
    
    Critical for ownership-aware IDOR detection:
    - user_id: Who is making the request
    - resource_owner_id: Who owns/created the resource being accessed
    - is_accessing_own_resource(): Quick ownership check
    
    RUM Sources:
    - DataDog: session_id, view_id, application_id
    - CloudFlare: cf_ray_id, cf_pageload_id
    """
    # User Identity
    user_id: str = Field(
        ..., 
        description="Authenticated user ID making the request"
    )
    user_email: Optional[str] = Field(
        None, 
        description="User email for correlation and context"
    )
    
    # DataDog RUM Headers
    datadog_session_id: Optional[str] = Field(
        None,
        description="DataDog RUM session identifier (x-datadog-session-id)",
        alias="dd_session_id"
    )
    datadog_view_id: Optional[str] = Field(
        None,
        description="DataDog RUM view/page identifier (x-datadog-view-id)",
        alias="dd_view_id"
    )
    datadog_application_id: Optional[str] = Field(
        None,
        description="DataDog RUM application identifier (x-datadog-application-id)",
        alias="dd_application_id"
    )
    
    # CloudFlare Analytics Headers
    cf_ray_id: Optional[str] = Field(
        None,
        description="CloudFlare Ray ID for request tracing (cf-ray)"
    )
    cf_pageload_id: Optional[str] = Field(
        None,
        description="CloudFlare pageload identifier (x-pageload-id)"
    )
    
    # Resource Access Context
    resource_type: ResourceType = Field(
        ...,
        description="Type of resource being accessed"
    )
    resource_id: str = Field(
        ...,
        description="Unique identifier of the resource (e.g., loan_id: 4395668)"
    )
    resource_owner_id: Optional[str] = Field(
        None,
        description="User ID of who created/owns this resource"
    )
    
    # Request Details
    http_method: str = Field(
        ...,
        description="HTTP method (GET, POST, PUT, DELETE, etc.)"
    )
    request_path: Optional[str] = Field(
        None,
        description="Full request path (e.g., /consumer/loan_applications/4395668)"
    )
    
    # Failure Details (populated on 403/AuthZ failure)
    failure_type: Optional[FailureType] = Field(
        None,
        description="Type of authorization failure, if applicable"
    )
    failure_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the failure occurred"
    )
    
    # Client Context
    user_agent: Optional[str] = Field(None, description="User agent string")
    client_ip: Optional[str] = Field(None, description="Client IP address (after scrubbing)")
    
    class Config:
        populate_by_name = True  # Allow both field name and alias
        json_schema_extra = {
            "example": {
                "user_id": "user_789",
                "user_email": "alice@example.com",
                "datadog_session_id": "d68ba5b9-7d1e-4ff5-9507-b870904cf55a",
                "datadog_view_id": "58b5b770-9d8b-4d17-9625-2f1dd1d73743",
                "datadog_application_id": "1326c560-2329-46a6-b276-f64b808e0321",
                "cf_ray_id": "7f2a1b3c4d5e6f7g",
                "resource_type": "loan_application",
                "resource_id": "4395668",
                "resource_owner_id": "user_456",
                "http_method": "GET",
                "request_path": "/consumer/loan_applications/4395668/offers",
                "failure_type": "authz_ownership_denied",
                "failure_timestamp": "2024-01-27T14:32:15Z"
            }
        }
    
    def is_accessing_own_resource(self) -> bool:
        """
        Check if the user is accessing their own resource.
        
        Core logic for ownership-aware IDOR detection:
        - Returns True if user_id matches resource_owner_id
        - Returns False if accessing another user's resource
        - Returns None if ownership is unknown (resource_owner_id not set)
        
        Usage in detection logic:
        - True → Legitimate access to own resource (no IDOR tracking)
        - False → Accessing OTHER user's resource (track for IDOR pattern)
        - None → Ownership unknown (lookup required before decision)
        """
        if self.resource_owner_id is None:
            return None
        return self.user_id == self.resource_owner_id
    
    def get_session_identifier(self) -> Optional[str]:
        """
        Get the primary session identifier.
        
        Prioritizes DataDog session_id, falls back to CF Ray ID.
        Used as the key for tracking failures in Redis.
        """
        return self.datadog_session_id or self.cf_ray_id


class AccessAttemptResult(str, Enum):
    """Outcome of access attempt analysis"""
    LEGITIMATE_ACCESS = "LEGITIMATE_ACCESS"  # User accessed own resource successfully
    LOG_ONLY = "LOG_ONLY"  # Single failure, no pattern detected
    ALERT_LOW = "ALERT_LOW"  # 2 distinct OTHER-user resources accessed
    ALERT_MEDIUM = "ALERT_MEDIUM"  # 3+ distinct but non-sequential
    CRITICAL_IDOR_ATTACK = "CRITICAL_IDOR_ATTACK"  # 3+ sequential OTHER-user resources


class IDORDetectionEvent(BaseModel):
    """
    Event emitted when IDOR pattern is detected.
    
    This is what gets sent to the SOAR system for incident response.
    """
    event_id: str = Field(..., description="Unique event identifier")
    detection_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the pattern was detected"
    )
    
    # User Context
    user_id: str = Field(..., description="User attempting access")
    session_id: str = Field(..., description="Session identifier")
    
    # Pattern Details
    severity: AccessAttemptResult = Field(
        ...,
        description="Severity of detected pattern"
    )
    distinct_resources_accessed: int = Field(
        ...,
        description="Number of distinct OTHER-user resources accessed"
    )
    is_sequential: bool = Field(
        ...,
        description="Whether resource IDs were sequential (stronger IDOR indicator)"
    )
    time_window_seconds: int = Field(
        ...,
        description="Time window in which pattern was detected"
    )
    
    # Evidence
    failed_resources: list[str] = Field(
        ...,
        description="List of resource IDs that failed authorization"
    )
    resource_owners: list[str] = Field(
        ...,
        description="List of owner IDs for the failed resources"
    )
    
    # Telemetry Context
    telemetry_snapshot: WebTelemetryMetadata = Field(
        ...,
        description="Most recent telemetry data point"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "idor_evt_20240127_143215_abc123",
                "detection_timestamp": "2024-01-27T14:32:15Z",
                "user_id": "user_789",
                "session_id": "d68ba5b9-7d1e-4ff5-9507-b870904cf55a",
                "severity": "CRITICAL_IDOR_ATTACK",
                "distinct_resources_accessed": 4,
                "is_sequential": True,
                "time_window_seconds": 45,
                "failed_resources": ["4395669", "4395670", "4395671", "4395672"],
                "resource_owners": ["user_456", "user_123", "user_890", "user_234"]
            }
        }
