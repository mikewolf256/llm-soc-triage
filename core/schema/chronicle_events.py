"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Pydantic models for Google Chronicle integration.

These schemas define data structures for Chronicle UDM events, API responses,
and SOAR integration. All models include security notes about PII handling.

Security Architecture:
    - Inbound schemas (UDMAlert) mark fields containing PII for scrubbing
    - Outbound schemas (CaseRequest, UDMAnnotation) assume pre-scrubbed data
    - Context schemas (Prevalence, Baseline) designed for LLM consumption
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ChronicleSeverity(str, Enum):
    """Chronicle alert severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChronicleUDMAlert(BaseModel):
    """
    Chronicle YARA-L alert webhook payload.
    
    Security Note:
        This schema represents RAW Chronicle data containing PII.
        Fields marked with [PII] must be scrubbed before LLM processing.
    
    Usage:
        alert = ChronicleUDMAlert(**webhook_payload)
        scrubbed_alert = scrub_pii(alert.model_dump())  # MANDATORY
    """
    
    # Alert Metadata
    rule_id: str = Field(
        ...,
        description="Chronicle YARA-L rule ID that triggered"
    )
    rule_name: str = Field(
        ...,
        description="Human-readable rule name"
    )
    rule_version: Optional[str] = Field(
        None,
        description="Rule version identifier"
    )
    
    # Timestamp
    detection_timestamp: datetime = Field(
        ...,
        description="When Chronicle detected this pattern",
        alias="timestamp"
    )
    
    # Severity
    severity: ChronicleSeverity = Field(
        default=ChronicleSeverity.MEDIUM,
        description="Chronicle-assigned severity"
    )
    
    # Raw UDM Events [PII WARNING]
    udm_events: List[Dict[str, Any]] = Field(
        ...,
        description="Raw UDM events (CONTAINS PII: IPs, emails, hostnames, usernames)"
    )
    
    # Aggregated Context
    distinct_resources: Optional[int] = Field(
        None,
        description="Count of distinct resources accessed (for IDOR rules)"
    )
    session_id: Optional[str] = Field(
        None,
        description="Session identifier from YARA-L match"
    )
    user_id: Optional[str] = Field(
        None,
        description="User identifier from YARA-L match [PII]"
    )
    
    # Risk Scoring
    risk_score: Optional[int] = Field(
        None,
        description="Chronicle risk score (0-100)",
        ge=0,
        le=100
    )
    
    class Config:
        populate_by_name = True
        json_schema_extra = {
            "security_note": "This model contains RAW UDM data with PII. "
                           "MUST scrub before LLM processing.",
            "pii_fields": ["udm_events", "user_id"],
        }


class ChroniclePrevalenceData(BaseModel):
    """
    Asset prevalence data from Chronicle (PII-scrubbed).
    
    Used to answer: "How many hosts have seen this IOC?"
    
    Security:
        Returned by ChronicleClient with PII already scrubbed.
        Asset names are [HOSTNAME_REDACTED] tokens.
    """
    
    indicator: str = Field(
        ...,
        description="IOC that was queried (hash, IP, domain)"
    )
    indicator_type: str = Field(
        ...,
        description="Type of indicator (hash, ip, domain, url)"
    )
    affected_assets: int = Field(
        ...,
        description="Count of assets that have seen this indicator",
        ge=0
    )
    first_seen: Optional[datetime] = Field(
        None,
        description="First time this indicator appeared in Chronicle"
    )
    last_seen: Optional[datetime] = Field(
        None,
        description="Most recent sighting of this indicator"
    )
    asset_names: List[str] = Field(
        default_factory=list,
        description="Scrubbed asset names ([HOSTNAME_REDACTED] tokens)"
    )
    
    class Config:
        json_schema_extra = {
            "security_note": "This model is returned pre-scrubbed by ChronicleClient. "
                           "Safe for LLM consumption.",
        }


class ChronicleUserBaseline(BaseModel):
    """
    User behavior baseline from Chronicle (PII-scrubbed).
    
    Used to answer: "Is this user behavior anomalous?"
    
    Security:
        Returned by ChronicleClient with PII scrubbed.
        IPs are [IP_REDACTED] tokens. Locations are city-level only.
    """
    
    user_id: str = Field(
        ...,
        description="User identifier (tokenized)"
    )
    typical_login_locations: List[str] = Field(
        default_factory=list,
        description="Common login locations (city-level, scrubbed addresses)"
    )
    typical_source_ips: List[str] = Field(
        default_factory=list,
        description="Common source IPs ([IP_REDACTED] tokens)"
    )
    typical_user_agents: List[str] = Field(
        default_factory=list,
        description="Common user agents (not PII, preserved)"
    )
    average_daily_logins: float = Field(
        default=0.0,
        description="Average number of logins per day",
        ge=0
    )
    baseline_period_days: int = Field(
        default=30,
        description="Number of days used to build baseline"
    )
    
    class Config:
        json_schema_extra = {
            "security_note": "This model is returned pre-scrubbed by ChronicleClient. "
                           "Safe for LLM consumption.",
        }


class ChronicleNetworkContext(BaseModel):
    """
    Network context for an IP from Chronicle (PII-scrubbed).
    
    Used to answer: "Has this IP connected to our infrastructure before?"
    
    Security:
        Returned by ChronicleClient with PII scrubbed.
        Connected asset names are [HOSTNAME_REDACTED] tokens.
    """
    
    ip_address: str = Field(
        ...,
        description="IP address queried ([IP_REDACTED] if scrubbed)"
    )
    first_seen: Optional[datetime] = Field(
        None,
        description="First connection from this IP"
    )
    last_seen: Optional[datetime] = Field(
        None,
        description="Most recent connection from this IP"
    )
    connection_count: int = Field(
        default=0,
        description="Total number of connections from this IP",
        ge=0
    )
    connected_assets: List[str] = Field(
        default_factory=list,
        description="Assets that communicated with this IP (scrubbed hostnames)"
    )
    reputation_score: Optional[int] = Field(
        None,
        description="Chronicle threat intelligence reputation (0-100, lower is worse)",
        ge=0,
        le=100
    )
    
    class Config:
        json_schema_extra = {
            "security_note": "This model is returned pre-scrubbed by ChronicleClient. "
                           "Safe for LLM consumption.",
        }


class ChronicleCaseRequest(BaseModel):
    """
    Chronicle SOAR case creation request.
    
    Security:
        PII scrubbing is OPTIONAL and configurable via SCRUB_PII_FOR_CHRONICLE.
        Default: false (Chronicle is internal, full context helpful for analysts).
        
        Use case fields are scrubbed if env var is set to "true".
    """
    
    # Case Identification
    title: str = Field(
        ...,
        description="Case title (concise summary)"
    )
    description: str = Field(
        ...,
        description="Detailed case description (may contain AI reasoning)"
    )
    
    # Classification
    severity: ChronicleSeverity = Field(
        ...,
        description="Case severity"
    )
    case_type: str = Field(
        default="security_incident",
        description="Type of case (security_incident, investigation, etc.)"
    )
    
    # Context
    alert_id: Optional[str] = Field(
        None,
        description="Original alert ID that triggered this case"
    )
    detection_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the detection occurred"
    )
    
    # IOCs and Evidence
    iocs: List[str] = Field(
        default_factory=list,
        description="Indicators of compromise"
    )
    affected_assets: List[str] = Field(
        default_factory=list,
        description="Affected assets (hostnames, IPs - may contain PII)"
    )
    affected_users: List[str] = Field(
        default_factory=list,
        description="Affected user IDs (may contain PII)"
    )
    
    # AI Context
    ai_reasoning: Optional[str] = Field(
        None,
        description="LLM's reasoning for this case creation"
    )
    confidence_score: Optional[float] = Field(
        None,
        description="AI confidence in this assessment (0.0-1.0)",
        ge=0.0,
        le=1.0
    )
    
    # MITRE ATT&CK
    mitre_tactics: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics (e.g., TA0009)"
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques (e.g., T1213)"
    )
    
    # Assignment
    assigned_to: Optional[str] = Field(
        None,
        description="Analyst or team to assign case to"
    )
    priority: Optional[str] = Field(
        default="medium",
        description="Case priority (low, medium, high, critical)"
    )
    
    class Config:
        json_schema_extra = {
            "security_note": "PII scrubbing is OPTIONAL (configurable). "
                           "Default: false for internal Chronicle instances.",
            "env_config": "SCRUB_PII_FOR_CHRONICLE=true to enable scrubbing",
        }


class ChronicleUDMAnnotation(BaseModel):
    """
    Chronicle UDM event annotation with AI context.
    
    Security:
        UDM annotations are ALWAYS PII-scrubbed (non-configurable).
        Reason: Long-term storage compliance (GDPR, SOC 2).
        
        ChronicleClient.annotate_udm_event() enforces scrubbing.
    """
    
    # Event Identification
    event_id: str = Field(
        ...,
        description="Chronicle UDM event ID to annotate"
    )
    event_timestamp: datetime = Field(
        ...,
        description="Original event timestamp"
    )
    
    # Annotation Content
    annotation_type: str = Field(
        default="ai_triage",
        description="Type of annotation (ai_triage, analyst_note, etc.)"
    )
    annotation_text: str = Field(
        ...,
        description="Annotation content (AI reasoning, already PII-scrubbed)"
    )
    
    # Triage Context
    triage_result: str = Field(
        ...,
        description="Triage disposition (FALSE_POSITIVE, TRUE_POSITIVE, etc.)"
    )
    confidence: float = Field(
        ...,
        description="AI confidence (0.0-1.0)",
        ge=0.0,
        le=1.0
    )
    
    # Classification
    severity_override: Optional[ChronicleSeverity] = Field(
        None,
        description="AI-recommended severity (if different from Chronicle)"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization (e.g., 'idor_attack', 'false_positive')"
    )
    
    # MITRE Mapping
    mitre_tactics: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics identified"
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques identified"
    )
    
    # Metadata
    annotated_by: str = Field(
        default="llm-soc-triage",
        description="System that created this annotation"
    )
    annotation_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this annotation was created"
    )
    
    class Config:
        json_schema_extra = {
            "security_note": "This model is ALWAYS PII-scrubbed before Chronicle write. "
                           "Non-configurable for compliance (long-term storage).",
            "compliance": "GDPR Article 5(1)(c) - Data Minimization",
        }


class ChronicleWebhookResponse(BaseModel):
    """
    Response sent back to Chronicle after webhook processing.
    
    Confirms receipt and provides middleware triage result.
    """
    
    success: bool = Field(
        ...,
        description="Whether webhook was successfully processed"
    )
    alert_id: str = Field(
        ...,
        description="Chronicle alert ID that was processed"
    )
    triage_result: Optional[str] = Field(
        None,
        description="Middleware triage result (if processed)"
    )
    confidence: Optional[float] = Field(
        None,
        description="Triage confidence score"
    )
    case_created: bool = Field(
        default=False,
        description="Whether a Chronicle case was auto-created"
    )
    case_id: Optional[str] = Field(
        None,
        description="Chronicle case ID (if created)"
    )
    processing_time_ms: Optional[int] = Field(
        None,
        description="Time taken to process webhook (milliseconds)"
    )
    error: Optional[str] = Field(
        None,
        description="Error message if processing failed"
    )


class ChronicleContextEnrichment(BaseModel):
    """
    Structured Chronicle context for LLM prompt injection.
    
    This is the output of ChronicleContextEnricher, formatted for
    inclusion in the LLM triage prompt.
    
    Security:
        All fields are pre-scrubbed by ChronicleClient.
        Safe for direct LLM consumption.
    """
    
    prevalence_context: Dict[str, str] = Field(
        default_factory=dict,
        description="IOC prevalence summaries (e.g., 'hash_abc: Seen on 3 hosts')"
    )
    user_baseline_context: Optional[str] = Field(
        None,
        description="User behavior baseline summary"
    )
    network_context: Dict[str, str] = Field(
        default_factory=dict,
        description="IP network context summaries"
    )
    historical_alerts: Optional[str] = Field(
        None,
        description="Similar historical alerts context"
    )
    
    def format_for_prompt(self) -> str:
        """
        Format Chronicle context as human-readable text for LLM prompt.
        
        Returns:
            Formatted string for inclusion in triage prompt
        """
        if not any([self.prevalence_context, self.user_baseline_context, self.network_context]):
            return ""
        
        lines = ["### Chronicle Security Context"]
        
        if self.prevalence_context:
            lines.append("\n**IOC Prevalence (Past 30 Days):**")
            for ioc, context in self.prevalence_context.items():
                lines.append(f"- `{ioc}`: {context}")
        
        if self.user_baseline_context:
            lines.append(f"\n**User Baseline:**\n{self.user_baseline_context}")
        
        if self.network_context:
            lines.append("\n**Network Intelligence:**")
            for ip, context in self.network_context.items():
                lines.append(f"- `{ip}`: {context}")
        
        if self.historical_alerts:
            lines.append(f"\n**Historical Context:**\n{self.historical_alerts}")
        
        return "\n".join(lines)
    
    class Config:
        json_schema_extra = {
            "security_note": "All fields are pre-scrubbed. Safe for LLM prompts.",
        }
