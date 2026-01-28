"""
Schema subpackage for specialized event types.

Organized by event source to maintain clean architectural boundaries:
- web_telemetry: Frontend RUM/telemetry and IDOR detection
- edr_events: Endpoint detection and response events

The parent core/schema.py handles high-level alert triage models.
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
]
