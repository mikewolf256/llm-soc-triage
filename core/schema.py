"""
Pydantic models for alert validation and response structure.
The single source of truth for data shapes.
"""

from pydantic import BaseModel, Field, validator
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
    Structured triage output from Claude
    """
    alert_id: str = Field(..., description="Original alert ID")
    triage_result: TriageResult = Field(..., description="Triage classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    reasoning: str = Field(..., description="Claude's analysis explanation")
    next_actions: List[str] = Field(..., description="Recommended next steps")
    iocs: List[str] = Field(default=[], description="Indicators of Compromise found")
    
    # Metadata
    processed_at: datetime = Field(default_factory=datetime.utcnow)
    model_used: Optional[str] = Field(None, description="Which LLM model was used")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "ALT-2024-001",
                "triage_result": "CRITICAL",
                "confidence": 0.92,
                "reasoning": "Base64 PowerShell with external C2 indicators and privilege escalation attempts",
                "next_actions": [
                    "Isolate endpoint immediately",
                    "Dump memory for malware analysis",
                    "Check for lateral movement to other hosts"
                ],
                "iocs": ["185.220.101.42", "update-checker.xyz"]
            }
        }
    
    @validator("confidence")
    def confidence_reasonable(cls, v):
        """Ensure confidence is between 0 and 1"""
        if not 0 <= v <= 1:
            raise ValueError("Confidence must be between 0 and 1")
        return v
