"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Pydantic models for EDR (Endpoint Detection and Response) event metadata.

This schema captures endpoint security events from EDR agents like
CrowdStrike Falcon, Microsoft Defender, Carbon Black, etc.

Separate from alert triage (core/schema.py) and web telemetry
(web_telemetry.py) to maintain clean architectural boundaries.

Used for enriching host-based security alerts with process, file,
network, and registry activity context.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ProcessAction(str, Enum):
    """Types of process actions"""
    CREATED = "created"
    TERMINATED = "terminated"
    MODIFIED = "modified"
    INJECTED = "injected"  # Code injection detected


class FileAction(str, Enum):
    """Types of file system actions"""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    EXECUTED = "executed"
    READ = "read"
    WRITE = "write"


class RegistryAction(str, Enum):
    """Types of Windows registry actions"""
    KEY_CREATED = "key_created"
    KEY_DELETED = "key_deleted"
    VALUE_SET = "value_set"
    VALUE_DELETED = "value_deleted"
    PERMISSIONS_MODIFIED = "permissions_modified"


class NetworkAction(str, Enum):
    """Types of network actions"""
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_CLOSED = "connection_closed"
    DNS_QUERY = "dns_query"
    LISTENING = "listening"
    DATA_TRANSFER = "data_transfer"


class EDREventMetadata(BaseModel):
    """
    Endpoint detection and response event metadata.
    
    Captures host-based security events from EDR agents to enrich
    alert triage with behavioral context.
    
    This is separate from:
    - AlertRequest (core/schema.py): High-level alert triage
    - WebTelemetryMetadata: Frontend RUM/session data
    
    Example Use Cases:
    - Process tree analysis for malware detection
    - File access patterns for data exfiltration
    - Registry persistence mechanism identification
    - Network C2 communication detection
    """
    # Endpoint Identity
    endpoint_id: str = Field(
        ...,
        description="Unique endpoint identifier (hostname, agent ID, etc.)"
    )
    hostname: Optional[str] = Field(
        None,
        description="Human-readable hostname"
    )
    endpoint_ip: Optional[str] = Field(
        None,
        description="Primary IP address of the endpoint"
    )
    os_type: Optional[str] = Field(
        None,
        description="Operating system (Windows, Linux, macOS)"
    )
    os_version: Optional[str] = Field(
        None,
        description="OS version (e.g., Windows 10 21H2, Ubuntu 22.04)"
    )
    
    # User Context
    username: Optional[str] = Field(
        None,
        description="User who triggered the event"
    )
    user_sid: Optional[str] = Field(
        None,
        description="Windows Security Identifier (SID)"
    )
    
    # Process Information
    process_name: Optional[str] = Field(
        None,
        description="Name of the process (e.g., powershell.exe, bash)"
    )
    process_id: Optional[int] = Field(
        None,
        description="Process ID (PID)"
    )
    process_path: Optional[str] = Field(
        None,
        description="Full path to the executable"
    )
    command_line: Optional[str] = Field(
        None,
        description="Full command line with arguments"
    )
    process_hash: Optional[str] = Field(
        None,
        description="SHA256 hash of the process binary"
    )
    process_action: Optional[ProcessAction] = Field(
        None,
        description="Action performed on the process"
    )
    
    # Parent Process Context
    parent_process: Optional[str] = Field(
        None,
        description="Parent process name"
    )
    parent_process_id: Optional[int] = Field(
        None,
        description="Parent process PID"
    )
    parent_command_line: Optional[str] = Field(
        None,
        description="Parent process command line"
    )
    
    # File System Activity
    file_path: Optional[str] = Field(
        None,
        description="Path to file involved in the event"
    )
    file_hash: Optional[str] = Field(
        None,
        description="SHA256 hash of the file"
    )
    file_action: Optional[FileAction] = Field(
        None,
        description="Action performed on the file"
    )
    
    # Registry Activity (Windows)
    registry_key: Optional[str] = Field(
        None,
        description="Windows registry key path"
    )
    registry_value: Optional[str] = Field(
        None,
        description="Registry value name"
    )
    registry_data: Optional[str] = Field(
        None,
        description="Registry value data"
    )
    registry_action: Optional[RegistryAction] = Field(
        None,
        description="Action performed on registry"
    )
    
    # Network Activity
    remote_ip: Optional[str] = Field(
        None,
        description="Remote IP address for network connections"
    )
    remote_port: Optional[int] = Field(
        None,
        description="Remote port number"
    )
    remote_hostname: Optional[str] = Field(
        None,
        description="Resolved remote hostname"
    )
    local_port: Optional[int] = Field(
        None,
        description="Local port number"
    )
    protocol: Optional[str] = Field(
        None,
        description="Network protocol (TCP, UDP, ICMP)"
    )
    network_action: Optional[NetworkAction] = Field(
        None,
        description="Type of network action"
    )
    bytes_sent: Optional[int] = Field(
        None,
        description="Number of bytes sent"
    )
    bytes_received: Optional[int] = Field(
        None,
        description="Number of bytes received"
    )
    
    # Threat Intelligence Context
    threat_name: Optional[str] = Field(
        None,
        description="Known threat/malware name if detected"
    )
    threat_family: Optional[str] = Field(
        None,
        description="Malware family classification"
    )
    mitre_tactics: Optional[List[str]] = Field(
        None,
        description="MITRE ATT&CK tactics (e.g., TA0001 - Initial Access)"
    )
    mitre_techniques: Optional[List[str]] = Field(
        None,
        description="MITRE ATT&CK techniques (e.g., T1059.001 - PowerShell)"
    )
    
    # Timestamps
    event_timestamp: datetime = Field(
        ...,
        description="When the event occurred on the endpoint"
    )
    ingestion_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the event was ingested by our system"
    )
    
    # EDR Agent Metadata
    agent_version: Optional[str] = Field(
        None,
        description="EDR agent version"
    )
    sensor_id: Optional[str] = Field(
        None,
        description="EDR sensor/agent identifier"
    )
    
    # Raw Event Data
    raw_event: Optional[Dict[str, Any]] = Field(
        None,
        description="Original raw event from EDR platform"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "endpoint_id": "LAPTOP-ABC123",
                "hostname": "LAPTOP-ABC123",
                "endpoint_ip": "10.0.1.45",
                "os_type": "Windows",
                "os_version": "Windows 10 21H2",
                "username": "john.doe",
                "process_name": "powershell.exe",
                "process_id": 4532,
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
                "process_hash": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c",
                "process_action": "created",
                "parent_process": "cmd.exe",
                "parent_process_id": 3214,
                "remote_ip": "185.220.101.42",
                "remote_port": 443,
                "protocol": "TCP",
                "network_action": "connection_established",
                "mitre_tactics": ["TA0002"],
                "mitre_techniques": ["T1059.001"],
                "event_timestamp": "2024-01-27T14:32:15Z"
            }
        }


class EDRAlertSummary(BaseModel):
    """
    High-level summary of EDR events for alert enrichment.
    
    Aggregates multiple EDREventMetadata entries into actionable context
    for the triage LLM.
    """
    total_events: int = Field(..., description="Total number of EDR events")
    unique_processes: int = Field(..., description="Distinct processes observed")
    unique_files: int = Field(..., description="Distinct files touched")
    unique_network_connections: int = Field(..., description="Distinct remote IPs contacted")
    
    # Behavioral Indicators
    has_code_injection: bool = Field(default=False)
    has_privilege_escalation: bool = Field(default=False)
    has_persistence_mechanism: bool = Field(default=False)
    has_data_exfiltration: bool = Field(default=False)
    has_lateral_movement: bool = Field(default=False)
    
    # Threat Context
    detected_threats: List[str] = Field(
        default=[],
        description="List of detected threat names"
    )
    mitre_tactics_observed: List[str] = Field(
        default=[],
        description="Unique MITRE ATT&CK tactics observed"
    )
    
    # Timeline
    first_event: datetime = Field(..., description="Timestamp of first event in sequence")
    last_event: datetime = Field(..., description="Timestamp of last event in sequence")
    duration_seconds: float = Field(..., description="Duration of event sequence")
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_events": 12,
                "unique_processes": 3,
                "unique_files": 5,
                "unique_network_connections": 2,
                "has_code_injection": True,
                "has_persistence_mechanism": True,
                "detected_threats": ["Cobalt Strike Beacon"],
                "mitre_tactics_observed": ["TA0002", "TA0003", "TA0011"],
                "first_event": "2024-01-27T14:32:15Z",
                "last_event": "2024-01-27T14:35:42Z",
                "duration_seconds": 207
            }
        }
