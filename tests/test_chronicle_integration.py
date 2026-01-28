"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Tests for Google Chronicle Integration

Test Coverage:
    1. PII scrubbing on UDM events (inbound gate)
    2. Chronicle API response parsing
    3. Webhook signature verification
    4. Context enrichment with PII scrubbing
    5. SOAR integration (case creation, UDM annotation)
    6. End-to-end webhook flow

Security Focus:
    All tests verify PII scrubbing at security boundaries per "Sandwich Model".
"""

import pytest
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, Any
from unittest.mock import Mock, patch, AsyncMock

from core.chronicle_integration import (
    ChronicleClient,
    ChronicleContextEnricher,
    ChronicleAlertHandler,
)
from core.schema.chronicle_events import (
    ChronicleUDMAlert,
    ChroniclePrevalenceData,
    ChronicleUserBaseline,
    ChronicleNetworkContext,
    ChronicleCaseRequest,
    ChronicleUDMAnnotation,
    ChronicleSeverity,
)
from core.scrubber import get_default_scrubber


@pytest.fixture
def chronicle_client():
    """Chronicle client with PII scrubbing enabled."""
    return ChronicleClient(
        credentials_file="/tmp/test_credentials.json",
        customer_id="test_customer",
        scrub_pii=True
    )


@pytest.fixture
def chronicle_enricher(chronicle_client):
    """Chronicle context enricher."""
    return ChronicleContextEnricher(chronicle_client)


@pytest.fixture
def chronicle_alert_handler():
    """Chronicle webhook alert handler."""
    return ChronicleAlertHandler(webhook_secret="test_secret_key")


@pytest.fixture
def sample_udm_alert() -> Dict[str, Any]:
    """Sample Chronicle UDM alert with PII."""
    return {
        "rule_id": "idor_sequential_enumeration_trigger",
        "rule_name": "IDOR Sequential Enumeration",
        "rule_version": "1.0",
        "timestamp": "2026-01-27T14:32:15Z",
        "severity": "MEDIUM",
        "udm_events": [
            {
                "metadata": {"event_type": "HTTP_REQUEST"},
                "network": {
                    "http": {
                        "method": "GET",
                        "response_code": 403,
                        "request_headers": {
                            "user-agent": "Mozilla/5.0",
                            "x-acme-id": "sess_abc123"
                        }
                    }
                },
                "target": {"url": "/api/v1/consumer/loan_applications/4395669"},
                "principal": {
                    "user": {"user_id": "user_789", "email_addresses": ["attacker@evil.com"]},
                    "ip": ["192.168.1.100"]
                }
            },
            {
                "metadata": {"event_type": "HTTP_REQUEST"},
                "network": {
                    "http": {
                        "method": "GET",
                        "response_code": 403,
                    }
                },
                "target": {"url": "/api/v1/consumer/loan_applications/4395670"},
                "principal": {
                    "user": {"user_id": "user_789", "email_addresses": ["attacker@evil.com"]},
                    "ip": ["192.168.1.100"],
                    "hostname": "attacker-laptop.evil.com"
                }
            }
        ],
        "distinct_resources": 4,
        "session_id": "sess_abc123",
        "user_id": "user_789",
        "risk_score": 75
    }


# ============================================================================
# Test Suite 1: PII Scrubbing on UDM Events (Inbound Gate - RED)
# ============================================================================

class TestUDMPIIScrubbing:
    """
    Test PII scrubbing on Chronicle UDM events.
    
    Security Requirement:
        Raw UDM events contain emails, IPs, hostnames. MUST scrub before LLM.
    """
    
    def test_scrub_udm_emails(self, chronicle_alert_handler, sample_udm_alert):
        """Test that emails are scrubbed from UDM events."""
        scrubbed = chronicle_alert_handler.scrub_webhook_alert(sample_udm_alert)
        
        # Emails should be redacted
        udm_json = json.dumps(scrubbed)
        assert "attacker@evil.com" not in udm_json
        assert "[EMAIL_REDACTED]" in udm_json or "email_addresses" not in udm_json
    
    def test_scrub_udm_ips(self, chronicle_alert_handler, sample_udm_alert):
        """Test that IP addresses are scrubbed from UDM events."""
        scrubbed = chronicle_alert_handler.scrub_webhook_alert(sample_udm_alert)
        
        # IPs should be redacted
        udm_json = json.dumps(scrubbed)
        assert "192.168.1.100" not in udm_json
        assert "[IP_REDACTED]" in udm_json or "ip" not in str(scrubbed)
    
    def test_scrub_udm_hostnames(self, chronicle_alert_handler, sample_udm_alert):
        """Test that hostnames are scrubbed from UDM events."""
        scrubbed = chronicle_alert_handler.scrub_webhook_alert(sample_udm_alert)
        
        # Hostnames should be redacted
        udm_json = json.dumps(scrubbed)
        assert "attacker-laptop.evil.com" not in udm_json
    
    def test_preserve_udm_structure(self, chronicle_alert_handler, sample_udm_alert):
        """Test that UDM structure is preserved after scrubbing."""
        scrubbed = chronicle_alert_handler.scrub_webhook_alert(sample_udm_alert)
        
        # Structure should be intact
        assert "rule_id" in scrubbed
        assert "udm_events" in scrubbed
        assert len(scrubbed["udm_events"]) == 2
        assert scrubbed["rule_id"] == "idor_sequential_enumeration_trigger"
    
    def test_preserve_correlation_tokens(self, chronicle_alert_handler, sample_udm_alert):
        """Test that correlation tokens (user_id, session_id) are preserved."""
        scrubbed = chronicle_alert_handler.scrub_webhook_alert(sample_udm_alert)
        
        # Correlation tokens should be preserved for LLM analysis
        assert scrubbed.get("user_id") == "user_789"
        assert scrubbed.get("session_id") == "sess_abc123"


# ============================================================================
# Test Suite 2: Webhook Signature Verification
# ============================================================================

class TestWebhookSignatureVerification:
    """
    Test Chronicle webhook signature verification.
    
    Security Requirement:
        Prevent webhook spoofing via HMAC signature validation.
    """
    
    def test_valid_signature(self, chronicle_alert_handler):
        """Test that valid signatures are accepted."""
        payload = b'{"test": "data"}'
        secret = "test_secret_key"
        
        # Compute valid signature
        expected_sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        signature_header = f"sha256={expected_sig}"
        
        # Should accept valid signature
        is_valid = chronicle_alert_handler.verify_signature(payload, signature_header)
        assert is_valid is True
    
    def test_invalid_signature(self, chronicle_alert_handler):
        """Test that invalid signatures are rejected."""
        payload = b'{"test": "data"}'
        signature_header = "sha256=invalid_signature_here"
        
        # Should reject invalid signature
        is_valid = chronicle_alert_handler.verify_signature(payload, signature_header)
        assert is_valid is False
    
    def test_tampered_payload(self, chronicle_alert_handler):
        """Test that tampered payloads are detected."""
        original_payload = b'{"test": "data"}'
        tampered_payload = b'{"test": "modified"}'
        secret = "test_secret_key"
        
        # Compute signature for original
        expected_sig = hmac.new(secret.encode(), original_payload, hashlib.sha256).hexdigest()
        signature_header = f"sha256={expected_sig}"
        
        # Should reject tampered payload
        is_valid = chronicle_alert_handler.verify_signature(tampered_payload, signature_header)
        assert is_valid is False


# ============================================================================
# Test Suite 3: Chronicle API Response Parsing with PII Scrubbing
# ============================================================================

class TestChronicleAPIResponses:
    """
    Test Chronicle API response parsing with PII scrubbing.
    
    Security Requirement:
        All API responses scrubbed before LLM context injection.
    """
    
    @pytest.mark.asyncio
    async def test_prevalence_response_scrubbing(self, chronicle_client):
        """Test that asset prevalence responses are PII-scrubbed."""
        # Mock Chronicle API response with PII
        mock_response = {
            "affected_asset_count": 3,
            "affected_asset_names": [
                "prod-server-01.company.com",
                "prod-server-02.company.com",
                "prod-server-03.company.com"
            ],
            "first_seen": "2026-01-10T14:32:00Z",
            "last_seen": "2026-01-27T09:15:00Z"
        }
        
        with patch.object(chronicle_client, '_api_call', return_value=mock_response):
            prevalence = await chronicle_client.get_asset_prevalence(
                indicator="abc123hash",
                indicator_type="hash"
            )
        
        # Hostnames should be scrubbed
        for asset_name in prevalence.asset_names:
            assert "prod-server" not in asset_name or "[HOSTNAME_REDACTED]" in asset_name
        
        # Counts should be preserved
        assert prevalence.affected_assets == 3
    
    @pytest.mark.asyncio
    async def test_user_baseline_response_scrubbing(self, chronicle_client):
        """Test that user baseline responses are PII-scrubbed."""
        # Mock Chronicle API response with PII
        mock_response = {
            "typical_locations": ["San Francisco, CA, 94107", "New York, NY, 10001"],
            "typical_source_ips": ["203.0.113.1", "203.0.113.2"],
            "typical_user_agents": ["Mozilla/5.0"],
            "average_daily_logins": 2.3
        }
        
        with patch.object(chronicle_client, '_api_call', return_value=mock_response):
            baseline = await chronicle_client.get_user_baseline("user_123")
        
        # IPs should be scrubbed
        for ip in baseline.typical_source_ips:
            assert "203.0.113" not in ip or "[IP_REDACTED]" in ip
        
        # City-level location preserved, specific addresses scrubbed
        for location in baseline.typical_login_locations:
            assert "," not in location or len(location.split(",")) == 1
    
    @pytest.mark.asyncio
    async def test_network_context_response_scrubbing(self, chronicle_client):
        """Test that network context responses are PII-scrubbed."""
        # Mock Chronicle API response with PII
        mock_response = {
            "first_seen": "2025-12-01T00:00:00Z",
            "last_seen": "2026-01-27T12:00:00Z",
            "connection_count": 15,
            "connected_assets": [
                "web-server-01.company.com",
                "api-gateway-02.company.com"
            ],
            "reputation_score": 75
        }
        
        with patch.object(chronicle_client, '_api_call', return_value=mock_response):
            context = await chronicle_client.get_network_context("1.2.3.4")
        
        # Connected assets (hostnames) should be scrubbed
        for asset in context.connected_assets:
            assert "web-server" not in asset or "[HOSTNAME_REDACTED]" in asset


# ============================================================================
# Test Suite 4: Context Enrichment Integration
# ============================================================================

class TestContextEnrichment:
    """
    Test Chronicle context enrichment with PII scrubbing.
    
    Security Requirement:
        Enrichment queries must return PII-scrubbed data for LLM consumption.
    """
    
    @pytest.mark.asyncio
    async def test_enrichment_formats_for_llm(self, chronicle_enricher):
        """Test that enrichment results are formatted for LLM prompts."""
        # Mock Chronicle client responses
        mock_prevalence = ChroniclePrevalenceData(
            indicator="abc123",
            indicator_type="hash",
            affected_assets=3,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            asset_names=["[HOSTNAME_REDACTED]"] * 3
        )
        
        with patch.object(
            chronicle_enricher.client,
            'get_asset_prevalence',
            return_value=mock_prevalence
        ):
            enrichment = await chronicle_enricher.enrich_from_chronicle(
                alert_iocs=["abc123hash"]
            )
        
        # Should have prevalence context
        assert "chronicle_prevalence" in enrichment
        
        # Should be formatted as string
        prevalence_text = enrichment["chronicle_prevalence"]["abc123"]
        assert isinstance(prevalence_text, str)
        assert "hosts" in prevalence_text.lower() or "endpoints" in prevalence_text.lower()
    
    @pytest.mark.asyncio
    async def test_enrichment_pii_scrubbed(self, chronicle_enricher):
        """Test that all enrichment data is PII-scrubbed."""
        # Mock responses with PII
        mock_baseline = ChronicleUserBaseline(
            user_id="user_123",
            typical_login_locations=["US-East"],
            typical_source_ips=["[IP_REDACTED]"],
            typical_user_agents=["Mozilla/5.0"],
            average_daily_logins=2.3
        )
        
        with patch.object(
            chronicle_enricher.client,
            'get_user_baseline',
            return_value=mock_baseline
        ):
            enrichment = await chronicle_enricher.enrich_from_chronicle(
                alert_iocs=[],
                affected_user="user_123"
            )
        
        # Should have user baseline context
        assert "chronicle_user_baseline" in enrichment
        
        # IPs should be scrubbed in formatted output
        baseline_text = enrichment["chronicle_user_baseline"]
        assert "203.0.113" not in baseline_text  # Sample IP should be scrubbed


# ============================================================================
# Test Suite 5: SOAR Integration (Case Creation and UDM Annotation)
# ============================================================================

class TestSOARIntegration:
    """
    Test Chronicle SOAR integration with configurable PII scrubbing.
    
    Security Requirements:
        - Case data: PII scrubbing configurable (default: false for internal)
        - UDM annotations: ALWAYS PII-scrubbed (compliance, non-configurable)
    """
    
    @pytest.mark.asyncio
    async def test_case_creation_pii_configurable(self, chronicle_client):
        """Test that Chronicle case creation respects PII scrubbing config."""
        case_request = ChronicleCaseRequest(
            title="Test Case",
            description="User attacker@evil.com attempted access from 192.168.1.100",
            severity=ChronicleSeverity.HIGH,
            affected_users=["attacker@evil.com"],
            iocs=["192.168.1.100"]
        )
        
        # Mock API response
        mock_response = {"case_id": "CHR-2026-001", "success": True}
        
        with patch.object(chronicle_client, '_api_call', return_value=mock_response):
            # Test with scrubbing enabled
            result = await chronicle_client.create_case(case_request, scrub_pii=True)
        
        assert result["success"] is True
        assert "case_id" in result
    
    @pytest.mark.asyncio
    async def test_udm_annotation_always_scrubbed(self, chronicle_client):
        """Test that UDM annotations are ALWAYS PII-scrubbed (non-configurable)."""
        annotation = ChronicleUDMAnnotation(
            event_id="udm_evt_123",
            event_timestamp=datetime.utcnow(),
            annotation_text="User attacker@evil.com from IP 192.168.1.100 attempted IDOR attack",
            triage_result="CRITICAL",
            confidence=0.95,
            mitre_tactics=["TA0009"],
            mitre_techniques=["T1213.002"]
        )
        
        # Mock scrubber to verify it's called
        scrubber_mock = Mock()
        scrubber_mock.scrub = Mock(return_value={"annotation_text": "[SCRUBBED]"})
        
        with patch.object(chronicle_client, 'scrubber', scrubber_mock):
            with patch.object(chronicle_client, '_api_call', return_value={"success": True}):
                result = await chronicle_client.annotate_udm_event(annotation)
        
        # Scrubber must be called (UDM annotations always scrubbed)
        assert scrubber_mock.scrub.called
        assert result["success"] is True


# ============================================================================
# Test Suite 6: End-to-End Webhook Flow
# ============================================================================

class TestEndToEndWebhookFlow:
    """
    Test complete webhook flow from Chronicle to middleware.
    
    Security Flow:
        Chronicle → Webhook → Signature Verify → PII Scrub → LLM → SOAR
    """
    
    @pytest.mark.asyncio
    async def test_webhook_flow_pii_scrubbed(self, chronicle_alert_handler, sample_udm_alert):
        """Test that entire webhook flow maintains PII scrubbing."""
        # Step 1: Verify signature
        payload = json.dumps(sample_udm_alert).encode()
        secret = "test_secret_key"
        signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        signature_header = f"sha256={signature}"
        
        is_valid = chronicle_alert_handler.verify_signature(payload, signature_header)
        assert is_valid is True
        
        # Step 2: Scrub PII from alert
        scrubbed_alert = chronicle_alert_handler.scrub_webhook_alert(sample_udm_alert)
        
        # Step 3: Verify no PII in scrubbed output
        scrubbed_json = json.dumps(scrubbed_alert)
        assert "attacker@evil.com" not in scrubbed_json
        assert "192.168.1.100" not in scrubbed_json
        assert "attacker-laptop.evil.com" not in scrubbed_json
        
        # Step 4: Verify structure preserved for LLM
        assert "rule_id" in scrubbed_alert
        assert "udm_events" in scrubbed_alert
        assert scrubbed_alert["user_id"] == "user_789"  # Correlation token preserved


# ============================================================================
# Test Suite 7: Schema Validation
# ============================================================================

class TestChronicleSchemas:
    """Test Pydantic schema validation for Chronicle models."""
    
    def test_udm_alert_schema_validation(self, sample_udm_alert):
        """Test that UDM alert schema validates correctly."""
        alert = ChronicleUDMAlert(**sample_udm_alert)
        
        assert alert.rule_id == "idor_sequential_enumeration_trigger"
        assert alert.severity == ChronicleSeverity.MEDIUM
        assert len(alert.udm_events) == 2
    
    def test_prevalence_data_schema(self):
        """Test prevalence data schema."""
        prevalence = ChroniclePrevalenceData(
            indicator="abc123",
            indicator_type="hash",
            affected_assets=5,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            asset_names=["[HOSTNAME_REDACTED]"] * 5
        )
        
        assert prevalence.affected_assets == 5
        assert len(prevalence.asset_names) == 5
    
    def test_case_request_schema(self):
        """Test case request schema."""
        case = ChronicleCaseRequest(
            title="Test Case",
            description="Test description",
            severity=ChronicleSeverity.HIGH,
            mitre_tactics=["TA0009"],
            mitre_techniques=["T1213"]
        )
        
        assert case.severity == ChronicleSeverity.HIGH
        assert "TA0009" in case.mitre_tactics


# ============================================================================
# Test Suite 8: Error Handling
# ============================================================================

class TestErrorHandling:
    """Test error handling in Chronicle integration."""
    
    @pytest.mark.asyncio
    async def test_api_timeout_handling(self, chronicle_client):
        """Test graceful handling of Chronicle API timeouts."""
        with patch.object(chronicle_client, '_api_call', side_effect=TimeoutError("API timeout")):
            prevalence = await chronicle_client.get_asset_prevalence("abc123")
        
        # Should return empty result on timeout, not crash
        assert prevalence.affected_assets == 0
    
    @pytest.mark.asyncio
    async def test_malformed_udm_handling(self, chronicle_alert_handler):
        """Test handling of malformed UDM events."""
        malformed_alert = {"invalid": "structure"}
        
        # Should not crash on malformed data
        try:
            scrubbed = chronicle_alert_handler.scrub_webhook_alert(malformed_alert)
            # If it doesn't crash, that's a pass
            assert isinstance(scrubbed, dict)
        except Exception as e:
            # If it raises, should be a validation error, not a crash
            assert "validation" in str(e).lower() or "schema" in str(e).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
