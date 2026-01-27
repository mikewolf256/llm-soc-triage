"""
Pydantic models for alert validation and response structure.

The single source of truth for data shapes with deterministic guardrails.

For regulated environments (fintech, healthcare), we enforce strict validation:
- LLM outputs must match predefined schemas
- Risk scores are bounded and validated
- Dispositions are strictly enumerated
- All fields are type-safe for downstream SOAR integration

This prevents the AI from "going rogue" and ensures auditability.
"""

from pydantic import BaseModel, Field, field_validator, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class AlertSeverity(str, Enum):
    """Standard severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TriageResult(str, Enum):
    """Triage outcomes"""
    FALSE_POSITIVE = "FALSE_POSITIVE"
    LOW_PRIORITY = "LOW_PRIORITY"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"
    CRITICAL = "CRITICAL"
    CONFIRMED_BREACH = "CONFIRMED_BREACH"


class AlertRequest(BaseModel):
    """
    Incoming alert structure - normalized from any source
    """
    alert_id: str = Field(..., description="Unique alert identifier")
    severity: AlertSeverity = Field(..., description="Alert severity level")
    source: str = Field(..., description="Alert source system (e.g., crowdstrike, splunk)")
    title: str = Field(..., description="Short alert title")
    description: str = Field(..., description="Detailed alert description")
    timestamp: datetime = Field(..., description="When the alert was generated")
    
    # Optional fields for enrichment
    affected_user: Optional[str] = Field(None, description="Username or email")
    affected_host: Optional[str] = Field(None, description="Hostname or IP")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Original alert payload")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "ALT-2024-001",
                "severity": "HIGH",
                "source": "crowdstrike",
                "title": "Suspicious PowerShell Execution",
                "description": "User executed base64-encoded PowerShell command",
                "timestamp": "2024-01-27T03:45:00Z",
                "affected_user": "john.doe@acme.com",
                "affected_host": "LAPTOP-ABC123"
            }
        }


class TriageResponse(BaseModel):
    """
    Structured triage output with deterministic guardrails
    
    Validation Strategy ("The Outbound Gate"):
    - Strict enum enforcement prevents invalid dispositions
    - Bounded numeric fields prevent nonsensical values
    - Required fields ensure completeness for SOAR ingestion
    - Type safety enables reliable downstream automation
    
    This ensures the LLM cannot produce outputs that would break
    our incident response workflow or violate compliance requirements.
    """
    alert_id: str = Field(..., description="Original alert ID")
    triage_result: TriageResult = Field(..., description="Triage classification - strictly validated")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    risk_score: int = Field(default=50, ge=0, le=100, description="Numeric risk score for prioritization")
    reasoning: str = Field(..., min_length=10, description="Claude's analysis explanation - must be substantive")
    next_actions: List[str] = Field(..., min_length=1, description="Recommended next steps - at least one required")
    iocs: List[str] = Field(default=[], description="Indicators of Compromise found")
    
    # Metadata
    processed_at: datetime = Field(default_factory=datetime.utcnow)
    model_used: Optional[str] = Field(None, description="Which LLM model was used")
    business_context_applied: bool = Field(default=False, description="Whether business context was used in triage")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "ALT-2024-001",
                "triage_result": "CRITICAL",
                "confidence": 0.92,
                "risk_score": 95,
                "reasoning": "Base64 PowerShell with external C2 indicators and privilege escalation attempts",
                "next_actions": [
                    "Isolate endpoint immediately",
                    "Dump memory for malware analysis",
                    "Check for lateral movement to other hosts"
                ],
                "iocs": ["185.220.101.42", "update-checker.xyz"],
                "business_context_applied": True
            }
        }
    
    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """
        Deterministic Guardrail: Confidence must be between 0 and 1
        
        In regulated environments, we cannot accept confidence scores
        outside this range as they would be meaningless for risk assessment.
        """
        if not 0 <= v <= 1:
            raise ValueError(f"Confidence must be between 0 and 1, got {v}")
        return v
    
    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: int) -> int:
        """
        Deterministic Guardrail: Risk score must be 0-100
        
        This normalized score enables prioritization and SLA routing.
        Values outside this range would break downstream automation.
        """
        if not 0 <= v <= 100:
            raise ValueError(f"Risk score must be between 0 and 100, got {v}")
        return v
    
    @field_validator("triage_result")
    @classmethod
    def validate_triage_result(cls, v: TriageResult) -> TriageResult:
        """
        Deterministic Guardrail: Only predefined dispositions are allowed
        
        The Enum already enforces this, but this validator provides
        explicit documentation of why we restrict to these values.
        
        These five dispositions map directly to our SOAR playbooks:
        - FALSE_POSITIVE → Auto-close with logging
        - LOW_PRIORITY → Queue for batch review
        - NEEDS_INVESTIGATION → Assign to analyst
        - CRITICAL → Page on-call team
        - CONFIRMED_BREACH → Execute IR playbook
        """
        return v
    
    @field_validator("next_actions")
    @classmethod
    def validate_next_actions(cls, v: List[str]) -> List[str]:
        """
        Deterministic Guardrail: At least one action must be provided
        
        Empty action lists are useless for analysts. This ensures
        every triage decision includes actionable guidance.
        """
        if not v or len(v) == 0:
            raise ValueError("At least one next action must be provided")
        
        # Filter out empty strings
        v = [action.strip() for action in v if action.strip()]
        
        if len(v) == 0:
            raise ValueError("Next actions cannot be empty strings")
        
        return v
    
    @field_validator("reasoning")
    @classmethod
    def validate_reasoning(cls, v: str) -> str:
        """
        Deterministic Guardrail: Reasoning must be substantive
        
        Single-word or trivial explanations don't meet audit requirements.
        We require at least 10 characters to ensure meaningful justification.
        """
        if len(v.strip()) < 10:
            raise ValueError("Reasoning must be at least 10 characters for audit trail")
        return v.strip()
    
    @field_validator("iocs")
    @classmethod
    def validate_iocs(cls, v: List[str]) -> List[str]:
        """
        Deterministic Guardrail: IOCs must be non-empty strings
        
        Filters out empty IOC entries that would break threat intel feeds.
        """
        return [ioc.strip() for ioc in v if ioc.strip()]
