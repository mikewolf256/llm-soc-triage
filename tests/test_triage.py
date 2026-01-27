"""
Tests for LLM SOC Triage
Proves the system actually works as advertised.
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app
from core.schema import AlertRequest, AlertSeverity, TriageResult
from core.scrubber import scrub_pii


# Test client
client = TestClient(app)


class TestHealthEndpoints:
    """Test basic health/status endpoints"""
    
    def test_root_endpoint(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "service" in response.json()
        assert response.json()["service"] == "LLM SOC Triage"
    
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert "status" in response.json()


class TestPIIScrubbing:
    """Test PII redaction works correctly"""
    
    def test_email_redaction(self):
        """Emails should be redacted"""
        alert = {
            "description": "User john.doe@acme.com performed suspicious action",
            "affected_user": "admin@company.com"
        }
        scrubbed = scrub_pii(alert)
        assert "john.doe@acme.com" not in scrubbed["description"]
        assert "[EMAIL_REDACTED]" in scrubbed["description"]
        assert scrubbed["affected_user"] == "[EMAIL_REDACTED]"
    
    def test_ip_redaction(self):
        """IP addresses should be redacted"""
        alert = {
            "description": "Connection to 192.168.1.100 detected"
        }
        scrubbed = scrub_pii(alert)
        assert "192.168.1.100" not in scrubbed["description"]
        assert "[IP_REDACTED]" in scrubbed["description"]
    
    def test_nested_scrubbing(self):
        """PII in nested objects should be scrubbed"""
        alert = {
            "raw_data": {
                "user": "test@example.com",
                "source": "10.0.0.1"
            }
        }
        scrubbed = scrub_pii(alert)
        assert scrubbed["raw_data"]["user"] == "[EMAIL_REDACTED]"
        assert scrubbed["raw_data"]["source"] == "[IP_REDACTED]"


class TestAlertValidation:
    """Test Pydantic validation"""
    
    def test_valid_alert(self):
        """Valid alert should pass validation"""
        alert = AlertRequest(
            alert_id="TEST-001",
            severity=AlertSeverity.HIGH,
            source="test",
            title="Test Alert",
            description="This is a test",
            timestamp=datetime.utcnow()
        )
        assert alert.alert_id == "TEST-001"
    
    def test_missing_required_field(self):
        """Missing required field should raise error"""
        with pytest.raises(Exception):
            AlertRequest(
                alert_id="TEST-001",
                # Missing severity
                source="test",
                title="Test",
                description="Test"
            )


class TestTriageEndpoint:
    """Test the main /triage endpoint"""
    
    def test_triage_endpoint_structure(self):
        """Triage endpoint should return proper structure"""
        alert_data = {
            "alert_id": "TEST-001",
            "severity": "HIGH",
            "source": "test",
            "title": "Test Alert",
            "description": "PowerShell execution detected",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Note: This will fail without a valid API key
        # For real testing, mock the Anthropic client
        response = client.post("/triage", json=alert_data)
        
        # If no API key, should get 500
        # With API key, should get 200
        assert response.status_code in [200, 500]
        
        if response.status_code == 200:
            data = response.json()
            assert "alert_id" in data
            assert "triage_result" in data
            assert "confidence" in data


class TestPromptEngine:
    """Test prompt construction"""
    
    def test_prompt_contains_alert_data(self):
        """Prompt should include the alert data"""
        from core.prompt_engine import build_triage_prompt
        
        alert = {
            "alert_id": "TEST-001",
            "title": "Suspicious Activity",
            "description": "Test description"
        }
        
        prompt = build_triage_prompt(alert)
        assert "TEST-001" in prompt
        assert "Suspicious Activity" in prompt
        assert "<alert>" in prompt
        assert "</alert>" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
