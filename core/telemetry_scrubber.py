"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Telemetry-aware PII scrubber that preserves detection context.

Key principle: Remove PII while keeping correlation tokens.
- user_email -> [EMAIL_REDACTED]
- client_ip  -> [IP_REDACTED] 
- Keep: user_id, session_id, resource_id, resource_owner_id (non-PII tokens)

This module provides specialized PII scrubbing for telemetry data that needs
to be sent to external systems (LLM APIs, SOAR platforms) while maintaining
the contextual information necessary for security analysis.
"""

from typing import Dict, Any
from core.schema.web_telemetry import IDORDetectionEvent, WebTelemetryMetadata
from core.scrubber import get_default_scrubber


def scrub_telemetry_for_llm(
    event: IDORDetectionEvent,
    telemetry: WebTelemetryMetadata
) -> Dict[str, Any]:
    """
    Scrub PII from event and telemetry, preserving detection context.
    
    This function removes sensitive PII (emails, IP addresses, etc.) while
    preserving correlation tokens (user_id, session_id, resource_id) that
    are essential for LLM analysis of attack patterns.
    
    Args:
        event: IDOR detection event containing attack pattern details
        telemetry: Web telemetry metadata with user and session context
    
    Returns:
        Dictionary representation of scrubbed data suitable for LLM analysis
    
    Example:
        >>> scrubbed = scrub_telemetry_for_llm(event, telemetry)
        >>> # user_email: "attacker@evil.com" -> "[EMAIL_REDACTED]"
        >>> # user_id: "usr_123" -> "usr_123" (preserved)
        >>> # client_ip: "192.168.1.100" -> "[IP_REDACTED]"
        >>> # session_id: "sess_abc" -> "sess_abc" (preserved)
    """
    scrubber = get_default_scrubber()
    
    # Convert to dicts for scrubbing
    event_dict = event.model_dump()
    telemetry_dict = telemetry.model_dump()
    
    # Combine for context
    combined_data = {
        "event_details": event_dict,
        "telemetry_context": telemetry_dict,
    }
    
    # Scrub PII (emails, IPs) via existing scrubber
    # The scrubber will recursively process nested structures
    scrubbed_data = scrubber.scrub(combined_data)
    
    return scrubbed_data


def scrub_event_for_soar(
    event: IDORDetectionEvent
) -> IDORDetectionEvent:
    """
    Scrub PII from detection event for SOAR transmission.
    
    This function creates a new event with PII redacted from the telemetry
    snapshot, while preserving all other event fields and correlation tokens.
    
    Args:
        event: Original IDOR detection event
    
    Returns:
        New IDORDetectionEvent with PII redacted from telemetry snapshot
    
    Example:
        >>> scrubbed_event = scrub_event_for_soar(event)
        >>> # event.telemetry_snapshot.user_email: [EMAIL_REDACTED]
        >>> # event.telemetry_snapshot.user_id: preserved
    """
    scrubber = get_default_scrubber()
    
    # Scrub the telemetry snapshot (contains user_email, client_ip, etc.)
    scrubbed_snapshot_dict = scrubber.scrub(event.telemetry_snapshot.model_dump())
    
    # Create new telemetry object with scrubbed data
    scrubbed_snapshot = WebTelemetryMetadata(**scrubbed_snapshot_dict)
    
    # Return new event with scrubbed snapshot
    # Using model_copy to create a shallow copy with updated field
    return event.model_copy(update={"telemetry_snapshot": scrubbed_snapshot})
