"""
Schema subpackage for specialized event types.

Organized by event source to maintain clean architectural boundaries:
- web_telemetry: Frontend RUM/telemetry and IDOR detection
- edr_events: Endpoint detection and response events
- chronicle_events: Chronicle UDM and SOAR integration

Note: Main triage models (AlertRequest, TriageResponse) are in core.schema module (parent).
Import those from core.schema, not from core.schema package.
"""

from .web_telemetry import (
    ResourceType,
    FailureType,
    WebTelemetryMetadata,
    AccessAttemptResult,
    IDORDetectionEvent,
)

from .edr_events import (
    ProcessAction,
    FileAction,
    RegistryAction,
    NetworkAction,
    EDREventMetadata,
    EDRAlertSummary,
)

from .chronicle_events import (
    ChronicleUDMAlert,
    ChroniclePrevalenceData,
    ChronicleUserBaseline,
    ChronicleNetworkContext,
    ChronicleCaseRequest,
    ChronicleUDMAnnotation,
    ChronicleWebhookResponse,
    ChronicleSeverity,
)

__all__ = [
    # Web Telemetry
    "ResourceType",
    "FailureType",
    "WebTelemetryMetadata",
    "AccessAttemptResult",
    "IDORDetectionEvent",
    # EDR Events
    "ProcessAction",
    "FileAction",
    "RegistryAction",
    "NetworkAction",
    "EDREventMetadata",
    "EDRAlertSummary",
    # Chronicle Events
    "ChronicleUDMAlert",
    "ChroniclePrevalenceData",
    "ChronicleUserBaseline",
    "ChronicleNetworkContext",
    "ChronicleCaseRequest",
    "ChronicleUDMAnnotation",
    "ChronicleWebhookResponse",
    "ChronicleSeverity",
]
