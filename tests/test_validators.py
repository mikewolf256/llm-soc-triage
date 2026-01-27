"""
Tests for Pydantic Validators - The "Deterministic Guardrails"

These tests prove the system enforces strict validation to prevent
the AI from "going rogue" in regulated environments.

Interview Point: "In fintech, you can't have an LLM returning risk_score=9000
or disposition='MAYBE_ITS_FINE'. These validators enforce the contract."
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.schema import TriageResponse, TriageResult


class TestTriageResponseValidation:
    """
    Test the Outbound Gate - ensures LLM outputs are deterministic
    """
    
    def test_valid_triage_response(self):
        """Valid response should pass all validators"""
        response = TriageResponse(
            alert_id="TEST-001",
            triage_result=TriageResult.CRITICAL,
            confidence=0.92,
            risk_score=85,
            reasoning="This is a detailed analysis of the security incident",
            next_actions=["Isolate endpoint", "Investigate further"],
            iocs=["192.168.1.100", "malware.exe"]
        )
        
        assert response.alert_id == "TEST-001"
        assert response.triage_result == TriageResult.CRITICAL
        assert response.risk_score == 85
        assert response.confidence == 0.92
    
    def test_confidence_too_low(self):
        """Confidence below 0 should be rejected"""
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-002",
                triage_result=TriageResult.NEEDS_INVESTIGATION,
                confidence=-0.5,  # Invalid
                risk_score=50,
                reasoning="Test reasoning here",
                next_actions=["Review"]
            )
        
        assert "confidence" in str(exc_info.value).lower()
    
    def test_confidence_too_high(self):
        """Confidence above 1 should be rejected"""
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-003",
                triage_result=TriageResult.NEEDS_INVESTIGATION,
                confidence=1.5,  # Invalid
                risk_score=50,
                reasoning="Test reasoning here",
                next_actions=["Review"]
            )
        
        assert "confidence" in str(exc_info.value).lower()
    
    def test_risk_score_below_zero(self):
        """Risk score below 0 should be rejected"""
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-004",
                triage_result=TriageResult.LOW_PRIORITY,
                confidence=0.5,
                risk_score=-10,  # Invalid
                reasoning="Test reasoning here",
                next_actions=["Review"]
            )
        
        assert "risk_score" in str(exc_info.value).lower()
    
    def test_risk_score_above_hundred(self):
        """Risk score above 100 should be rejected"""
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-005",
                triage_result=TriageResult.CRITICAL,
                confidence=0.9,
                risk_score=150,  # Invalid
                reasoning="Test reasoning here",
                next_actions=["Escalate"]
            )
        
        assert "risk_score" in str(exc_info.value).lower()
    
    def test_invalid_triage_result(self):
        """
        Invalid triage result should be rejected
        
        This proves we only accept predefined dispositions that map
        to SOAR playbooks.
        """
        with pytest.raises(ValidationError):
            TriageResponse(
                alert_id="TEST-006",
                triage_result="MAYBE_ITS_FINE",  # Not in enum
                confidence=0.5,
                risk_score=50,
                reasoning="Test reasoning here",
                next_actions=["Review"]
            )
    
    def test_empty_next_actions(self):
        """Empty next_actions should be rejected"""
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-007",
                triage_result=TriageResult.NEEDS_INVESTIGATION,
                confidence=0.7,
                risk_score=60,
                reasoning="Test reasoning here",
                next_actions=[]  # Invalid - must have at least one
            )
        
        assert "next_actions" in str(exc_info.value).lower()
    
    def test_next_actions_with_empty_strings(self):
        """Next actions with only empty strings should be rejected"""
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-008",
                triage_result=TriageResult.NEEDS_INVESTIGATION,
                confidence=0.7,
                risk_score=60,
                reasoning="Test reasoning here",
                next_actions=["", "  ", ""]  # All empty/whitespace
            )
        
        assert "next_actions" in str(exc_info.value).lower()
    
    def test_reasoning_too_short(self):
        """
        Reasoning less than 10 characters should be rejected
        
        Interview Point: "In regulated environments, we need meaningful
        justification for audit trails, not single-word explanations."
        """
        with pytest.raises(ValidationError) as exc_info:
            TriageResponse(
                alert_id="TEST-009",
                triage_result=TriageResult.FALSE_POSITIVE,
                confidence=0.9,
                risk_score=10,
                reasoning="bad",  # Too short
                next_actions=["Close"]
            )
        
        assert "reasoning" in str(exc_info.value).lower()
    
    def test_iocs_with_empty_strings_filtered(self):
        """Empty IOC entries should be filtered out"""
        response = TriageResponse(
            alert_id="TEST-010",
            triage_result=TriageResult.CRITICAL,
            confidence=0.95,
            risk_score=90,
            reasoning="Malware detected with known C2 infrastructure",
            next_actions=["Isolate endpoint"],
            iocs=["192.168.1.100", "", "  ", "malware.exe", ""]
        )
        
        # Empty strings should be filtered
        assert "" not in response.iocs
        assert "192.168.1.100" in response.iocs
        assert "malware.exe" in response.iocs
        assert len(response.iocs) == 2
    
    def test_boundary_values_valid(self):
        """Test boundary values that should be valid"""
        # Min valid values
        response_min = TriageResponse(
            alert_id="TEST-011",
            triage_result=TriageResult.FALSE_POSITIVE,
            confidence=0.0,  # Minimum valid
            risk_score=0,  # Minimum valid
            reasoning="Minimum valid reasoning test",
            next_actions=["Close"]
        )
        assert response_min.confidence == 0.0
        assert response_min.risk_score == 0
        
        # Max valid values
        response_max = TriageResponse(
            alert_id="TEST-012",
            triage_result=TriageResult.CONFIRMED_BREACH,
            confidence=1.0,  # Maximum valid
            risk_score=100,  # Maximum valid
            reasoning="Maximum valid reasoning test",
            next_actions=["Execute IR playbook"]
        )
        assert response_max.confidence == 1.0
        assert response_max.risk_score == 100
    
    def test_metadata_fields_populated(self):
        """Verify metadata fields are automatically populated"""
        response = TriageResponse(
            alert_id="TEST-013",
            triage_result=TriageResult.NEEDS_INVESTIGATION,
            confidence=0.7,
            risk_score=65,
            reasoning="Test for metadata population",
            next_actions=["Investigate"]
        )
        
        # processed_at should be auto-populated
        assert isinstance(response.processed_at, datetime)
        
        # business_context_applied defaults to False
        assert response.business_context_applied == False
    
    def test_real_world_llm_output_validation(self):
        """
        Test that a realistic LLM response structure is validated correctly
        
        Interview Point: "This is what we'd actually get from Claude.
        The validators ensure it matches our SOAR requirements."
        """
        response = TriageResponse(
            alert_id="CRS-2026-0042",
            triage_result=TriageResult.CRITICAL,
            confidence=0.92,
            risk_score=95,
            reasoning="Base64-encoded PowerShell execution with external C2 contact to known Cobalt Strike infrastructure. Process injection detected indicating active compromise.",
            next_actions=[
                "IMMEDIATELY isolate endpoint from network",
                "Dump memory for malware analysis",
                "Check EDR timeline for lateral movement indicators",
                "Pull full network logs for past 72 hours"
            ],
            iocs=[
                "185.220.101.42",
                "update-checker.xyz",
                "SHA256:a3b2c1d4e5f6789012345678901234567890abcdef"
            ],
            model_used="claude-3-5-sonnet-20241022",
            business_context_applied=True
        )
        
        assert response.alert_id == "CRS-2026-0042"
        assert response.triage_result == TriageResult.CRITICAL
        assert len(response.next_actions) == 4
        assert len(response.iocs) == 3
        assert response.business_context_applied == True


class TestTriageResultEnum:
    """Test that triage result enum values are strictly enforced"""
    
    def test_all_enum_values_valid(self):
        """All defined enum values should be usable"""
        valid_results = [
            TriageResult.FALSE_POSITIVE,
            TriageResult.LOW_PRIORITY,
            TriageResult.NEEDS_INVESTIGATION,
            TriageResult.CRITICAL,
            TriageResult.CONFIRMED_BREACH
        ]
        
        for result in valid_results:
            response = TriageResponse(
                alert_id="TEST-ENUM",
                triage_result=result,
                confidence=0.8,
                risk_score=50,
                reasoning="Testing enum values",
                next_actions=["Test action"]
            )
            assert response.triage_result == result
    
    def test_enum_string_values(self):
        """Verify enum string values match expected SOAR dispositions"""
        assert TriageResult.FALSE_POSITIVE.value == "FALSE_POSITIVE"
        assert TriageResult.LOW_PRIORITY.value == "LOW_PRIORITY"
        assert TriageResult.NEEDS_INVESTIGATION.value == "NEEDS_INVESTIGATION"
        assert TriageResult.CRITICAL.value == "CRITICAL"
        assert TriageResult.CONFIRMED_BREACH.value == "CONFIRMED_BREACH"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
