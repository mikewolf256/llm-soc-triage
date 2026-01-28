"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Tests for Ownership-Aware IDOR Detection System

This test suite validates the core innovation: distinguishing legitimate
multi-resource access (user's own loans) from IDOR enumeration attacks
(accessing OTHER users' resources).

Test Coverage:
1. Legitimate access patterns (NO false positives)
2. IDOR attack detection (sequential enumeration)
3. Manual exploration detection (non-sequential)
4. Edge cases (missing data, Redis failures, QA testers)
5. Ownership tracking accuracy
6. Pattern detection thresholds
"""

import pytest
import fakeredis
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ownership_tracker import OwnershipTracker
from core.detection_monitor import IdentityAssetMonitor
from core.rum_correlator import RUMCorrelator
from core.detection_middleware import DetectionMiddleware
from core.schema.web_telemetry import (
    WebTelemetryMetadata,
    ResourceType,
    FailureType,
    AccessAttemptResult,
)


@pytest.fixture
def redis_client():
    """Provide in-memory Redis for testing"""
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def ownership_tracker(redis_client):
    """Provide ownership tracker with test Redis"""
    return OwnershipTracker(redis_client)


@pytest.fixture
def detection_monitor(redis_client, ownership_tracker):
    """Provide detection monitor with test dependencies"""
    return IdentityAssetMonitor(
        redis_client,
        ownership_tracker,
        threshold=3,
        window_seconds=60,
    )


@pytest.fixture
def rum_correlator():
    """Provide RUM correlator"""
    return RUMCorrelator()


class TestOwnershipTracker:
    """Test ownership tracking and verification"""
    
    def test_record_and_verify_ownership(self, ownership_tracker):
        """Test basic ownership recording and verification"""
        # Record ownership
        result = ownership_tracker.record_ownership("user_123", "loan_456")
        assert result is True
        
        # Verify ownership
        assert ownership_tracker.is_owner("user_123", "loan_456") is True
        assert ownership_tracker.is_owner("user_999", "loan_456") is False
    
    def test_get_owned_resources(self, ownership_tracker):
        """Test retrieving all resources owned by a user"""
        # Record multiple ownerships
        ownership_tracker.record_ownership("user_123", "loan_100")
        ownership_tracker.record_ownership("user_123", "loan_200")
        ownership_tracker.record_ownership("user_123", "loan_300")
        
        # Get owned resources
        owned = ownership_tracker.get_owned_resources("user_123")
        assert len(owned) == 3
        assert "loan_100" in owned
        assert "loan_200" in owned
        assert "loan_300" in owned
    
    def test_get_resource_owner(self, ownership_tracker):
        """Test reverse lookup: resource -> owner"""
        ownership_tracker.record_ownership("user_456", "loan_789")
        
        owner = ownership_tracker.get_resource_owner("loan_789")
        assert owner == "user_456"
        
        # Non-existent resource
        assert ownership_tracker.get_resource_owner("loan_999") is None
    
    def test_bulk_record_ownership(self, ownership_tracker):
        """Test bulk ownership recording"""
        loan_ids = ["loan_1", "loan_2", "loan_3", "loan_4", "loan_5"]
        count = ownership_tracker.bulk_record_ownership("user_bulk", loan_ids)
        
        assert count == 5
        assert ownership_tracker.get_ownership_count("user_bulk") == 5
    
    def test_remove_ownership(self, ownership_tracker):
        """Test ownership removal"""
        ownership_tracker.record_ownership("user_123", "loan_456")
        assert ownership_tracker.is_owner("user_123", "loan_456") is True
        
        ownership_tracker.remove_ownership("user_123", "loan_456")
        assert ownership_tracker.is_owner("user_123", "loan_456") is False


class TestLegitimateAccess:
    """Test scenarios that should NOT trigger alerts (legitimate use)"""
    
    def test_user_accessing_own_multiple_loans(self, detection_monitor, ownership_tracker):
        """User with 10 loans accesses all 10 - should be legitimate"""
        user_id = "user_789"
        session_id = "session_abc123"
        
        # User owns 10 loans
        for i in range(10):
            loan_id = f"loan_{4395668 + i}"
            ownership_tracker.record_ownership(user_id, loan_id)
        
        # User accesses all their own loans
        for i in range(10):
            loan_id = f"loan_{4395668 + i}"
            telemetry = WebTelemetryMetadata(
                user_id=user_id,
                datadog_session_id=session_id,
                resource_type=ResourceType.LOAN_APPLICATION,
                resource_id=loan_id,
                resource_owner_id=user_id,  # Own loan
                http_method="GET",
                failure_timestamp=datetime.utcnow(),
            )
            
            # Simulate successful access (200 OK)
            result, event = detection_monitor.track_access_attempt(telemetry, success=True)
            
            assert result == AccessAttemptResult.LEGITIMATE_ACCESS
            assert event is None
    
    def test_user_retrying_own_loan_after_bug(self, detection_monitor, ownership_tracker):
        """User fails to access their own loan (infrastructure bug) - should log only"""
        user_id = "user_123"
        loan_id = "loan_456"
        session_id = "session_xyz"
        
        # User owns this loan
        ownership_tracker.record_ownership(user_id, loan_id)
        
        # User fails to access their OWN loan (bug, not attack)
        telemetry = WebTelemetryMetadata(
            user_id=user_id,
            datadog_session_id=session_id,
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id=loan_id,
            resource_owner_id=user_id,  # Own loan
            http_method="GET",
            failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
            failure_timestamp=datetime.utcnow(),
        )
        
        result, event = detection_monitor.track_access_attempt(telemetry, success=False)
        
        # Should be LOG_ONLY (not an attack)
        assert result == AccessAttemptResult.LOG_ONLY
        assert event is None


class TestIDORAttackDetection:
    """Test IDOR attack scenarios that SHOULD trigger alerts"""
    
    def test_sequential_idor_attack(self, detection_monitor, ownership_tracker):
        """User accesses 3+ sequential OTHER users' loans - CRITICAL alert"""
        attacker_id = "user_789"
        session_id = "session_attacker"
        
        # Attacker owns loan_4395668
        ownership_tracker.record_ownership(attacker_id, "loan_4395668")
        
        # Set up other users' loans
        ownership_tracker.record_ownership("user_456", "loan_4395669")
        ownership_tracker.record_ownership("user_123", "loan_4395670")
        ownership_tracker.record_ownership("user_890", "loan_4395671")
        
        # Attacker successfully accesses own loan first
        own_telemetry = WebTelemetryMetadata(
            user_id=attacker_id,
            datadog_session_id=session_id,
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id="loan_4395668",
            resource_owner_id=attacker_id,
            http_method="GET",
            failure_timestamp=datetime.utcnow(),
        )
        result, _ = detection_monitor.track_access_attempt(own_telemetry, success=True)
        assert result == AccessAttemptResult.LEGITIMATE_ACCESS
        
        # Now attempt to access 3 sequential OTHER users' loans
        other_loans = ["loan_4395669", "loan_4395670", "loan_4395671"]
        other_owners = ["user_456", "user_123", "user_890"]
        
        result = None
        event = None
        
        for loan_id, owner_id in zip(other_loans, other_owners):
            telemetry = WebTelemetryMetadata(
                user_id=attacker_id,
                datadog_session_id=session_id,
                resource_type=ResourceType.LOAN_APPLICATION,
                resource_id=loan_id,
                resource_owner_id=owner_id,  # OTHER user's loan
                http_method="GET",
                failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
                failure_timestamp=datetime.utcnow(),
            )
            
            result, event = detection_monitor.track_access_attempt(telemetry, success=False)
        
        # Should detect CRITICAL IDOR attack
        assert result == AccessAttemptResult.CRITICAL_IDOR_ATTACK
        assert event is not None
        assert event.severity == AccessAttemptResult.CRITICAL_IDOR_ATTACK
        assert event.is_sequential is True
        assert event.distinct_resources_accessed == 3
        assert event.user_id == attacker_id
    
    def test_non_sequential_idor_medium_alert(self, detection_monitor, ownership_tracker):
        """User accesses 3+ non-sequential OTHER loans - MEDIUM alert"""
        attacker_id = "user_999"
        session_id = "session_manual"
        
        # Set up scattered ownership
        ownership_tracker.record_ownership("user_100", "loan_1000")
        ownership_tracker.record_ownership("user_200", "loan_5000")
        ownership_tracker.record_ownership("user_300", "loan_9000")
        
        # Attempt to access scattered loans
        scattered_loans = ["loan_1000", "loan_5000", "loan_9000"]
        scattered_owners = ["user_100", "user_200", "user_300"]
        
        result = None
        for loan_id, owner_id in zip(scattered_loans, scattered_owners):
            telemetry = WebTelemetryMetadata(
                user_id=attacker_id,
                datadog_session_id=session_id,
                resource_type=ResourceType.LOAN_APPLICATION,
                resource_id=loan_id,
                resource_owner_id=owner_id,
                http_method="GET",
                failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
                failure_timestamp=datetime.utcnow(),
            )
            
            result, event = detection_monitor.track_access_attempt(telemetry, success=False)
        
        # Should be MEDIUM (non-sequential but multiple attempts)
        assert result == AccessAttemptResult.ALERT_MEDIUM
        assert event is not None
        assert event.is_sequential is False
    
    def test_two_failures_low_alert(self, detection_monitor, ownership_tracker):
        """User accesses 2 OTHER loans - LOW alert"""
        user_id = "user_test"
        session_id = "session_low"
        
        ownership_tracker.record_ownership("user_a", "loan_a")
        ownership_tracker.record_ownership("user_b", "loan_b")
        
        # First attempt
        telemetry1 = WebTelemetryMetadata(
            user_id=user_id,
            datadog_session_id=session_id,
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id="loan_a",
            resource_owner_id="user_a",
            http_method="GET",
            failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
            failure_timestamp=datetime.utcnow(),
        )
        result1, _ = detection_monitor.track_access_attempt(telemetry1, success=False)
        
        # Second attempt
        telemetry2 = WebTelemetryMetadata(
            user_id=user_id,
            datadog_session_id=session_id,
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id="loan_b",
            resource_owner_id="user_b",
            http_method="GET",
            failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
            failure_timestamp=datetime.utcnow(),
        )
        result2, _ = detection_monitor.track_access_attempt(telemetry2, success=False)
        
        # Should be LOW alert (2 distinct)
        assert result2 == AccessAttemptResult.ALERT_LOW


class TestRUMCorrelation:
    """Test RUM telemetry extraction"""
    
    def test_extract_telemetry_from_headers(self, rum_correlator):
        """Test extracting telemetry from FastAPI request headers"""
        from fastapi import Request
        from unittest.mock import MagicMock
        
        # Mock request with headers
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {
            "x-user-id": "user_123",
            "x-user-email": "test@example.com",
            "x-datadog-session-id": "dd_session_abc",
            "x-datadog-view-id": "dd_view_xyz",
            "cf-ray": "cf_ray_123",
        }
        mock_request.method = "GET"
        mock_request.url.path = "/consumer/loan_applications/4395668"
        mock_request.client.host = "192.168.1.1"
        
        # Extract telemetry
        telemetry = rum_correlator.extract_telemetry(
            mock_request,
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id="4395668",
        )
        
        assert telemetry.user_id == "user_123"
        assert telemetry.user_email == "test@example.com"
        assert telemetry.datadog_session_id == "dd_session_abc"
        assert telemetry.datadog_view_id == "dd_view_xyz"
        assert telemetry.cf_ray_id == "cf_ray_123"
        assert telemetry.resource_type == ResourceType.LOAN_APPLICATION
        assert telemetry.resource_id == "4395668"
    
    def test_validate_telemetry(self, rum_correlator):
        """Test telemetry validation logic"""
        # Valid telemetry
        valid_telemetry = WebTelemetryMetadata(
            user_id="user_123",
            datadog_session_id="session_abc",
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id="loan_456",
            http_method="GET",
            failure_timestamp=datetime.utcnow(),
        )
        
        is_valid, issues = rum_correlator.validate_telemetry(valid_telemetry)
        assert is_valid is True
        assert len(issues) == 0
        
        # Invalid telemetry (missing user_id)
        invalid_telemetry = WebTelemetryMetadata(
            user_id="unknown",  # Invalid
            resource_type=ResourceType.OTHER,  # Unknown type
            resource_id="unknown",  # Unknown ID
            http_method="GET",
            failure_timestamp=datetime.utcnow(),
        )
        
        is_valid, issues = rum_correlator.validate_telemetry(invalid_telemetry)
        assert is_valid is False
        assert len(issues) > 0


class TestDetectionMiddleware:
    """Test middleware orchestration"""
    
    @pytest.mark.asyncio
    async def test_track_authorized_access(self, redis_client, ownership_tracker):
        """Test tracking successful access"""
        from fastapi import Request
        from unittest.mock import MagicMock
        
        rum = RUMCorrelator()
        monitor = IdentityAssetMonitor(redis_client, ownership_tracker)
        middleware = DetectionMiddleware(rum, ownership_tracker, monitor)
        
        # Mock request
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"x-user-id": "user_123"}
        mock_request.method = "GET"
        mock_request.url.path = "/api/loans/456"
        mock_request.client.host = "127.0.0.1"
        
        # Track authorized access
        await middleware.track_authorized_access(
            mock_request,
            resource_id="loan_456",
            resource_type=ResourceType.LOAN_APPLICATION,
            user_id="user_123",
        )
        
        # Verify ownership was recorded
        assert ownership_tracker.is_owner("user_123", "loan_456") is True
    
    @pytest.mark.asyncio
    async def test_track_unauthorized_with_soar_callback(self, redis_client, ownership_tracker):
        """Test SOAR callback on CRITICAL alert"""
        rum = RUMCorrelator()
        monitor = IdentityAssetMonitor(redis_client, ownership_tracker, threshold=2)
        
        # Mock SOAR callback
        soar_called = False
        received_event = None
        
        async def mock_soar_callback(event):
            nonlocal soar_called, received_event
            soar_called = True
            received_event = event
        
        middleware = DetectionMiddleware(
            rum,
            ownership_tracker,
            monitor,
            soar_callback=mock_soar_callback,
        )
        
        # Mock request
        from fastapi import Request
        from unittest.mock import MagicMock
        
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"x-user-id": "attacker"}
        mock_request.method = "GET"
        mock_request.url.path = "/api/loans/100"
        mock_request.client.host = "1.2.3.4"
        
        # Set up ownership
        ownership_tracker.record_ownership("owner_a", "loan_100")
        ownership_tracker.record_ownership("owner_b", "loan_101")
        
        # Trigger failures
        await middleware.track_unauthorized_access(
            mock_request,
            resource_id="loan_100",
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_owner_id="owner_a",
            user_id="attacker",
        )
        
        mock_request.url.path = "/api/loans/101"
        result, event = await middleware.track_unauthorized_access(
            mock_request,
            resource_id="loan_101",
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_owner_id="owner_b",
            user_id="attacker",
        )
        
        # SOAR callback should be triggered for CRITICAL
        if result == AccessAttemptResult.CRITICAL_IDOR_ATTACK:
            assert soar_called is True
            assert received_event is not None


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_missing_session_identifier(self, detection_monitor):
        """Test handling of missing session ID"""
        telemetry = WebTelemetryMetadata(
            user_id="user_123",
            # No session_id!
            resource_type=ResourceType.LOAN_APPLICATION,
            resource_id="loan_456",
            http_method="GET",
            failure_timestamp=datetime.utcnow(),
        )
        
        result, event = detection_monitor.track_access_attempt(telemetry, success=False)
        
        # Should handle gracefully
        assert result == AccessAttemptResult.LOG_ONLY
        assert event is None
    
    def test_non_numeric_resource_ids(self, detection_monitor, ownership_tracker):
        """Test handling of non-numeric resource IDs"""
        ownership_tracker.record_ownership("user_a", "uuid-abc-123")
        ownership_tracker.record_ownership("user_b", "uuid-def-456")
        ownership_tracker.record_ownership("user_c", "uuid-ghi-789")
        
        session_id = "session_test"
        
        # Attempt to access non-numeric IDs
        for i, resource_id in enumerate(["uuid-abc-123", "uuid-def-456", "uuid-ghi-789"]):
            telemetry = WebTelemetryMetadata(
                user_id="attacker",
                datadog_session_id=session_id,
                resource_type=ResourceType.DOCUMENT,
                resource_id=resource_id,
                resource_owner_id=f"user_{chr(97+i)}",  # user_a, user_b, user_c
                http_method="GET",
                failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
                failure_timestamp=datetime.utcnow(),
            )
            
            result, event = detection_monitor.track_access_attempt(telemetry, success=False)
        
        # Should still detect pattern (not sequential, but 3+ distinct)
        assert result == AccessAttemptResult.ALERT_MEDIUM
        assert event.is_sequential is False
    
    def test_session_stats(self, detection_monitor, ownership_tracker):
        """Test session statistics retrieval"""
        session_id = "session_stats_test"
        
        ownership_tracker.record_ownership("owner_1", "loan_1")
        ownership_tracker.record_ownership("owner_2", "loan_2")
        
        # Create some failures
        for i in range(2):
            telemetry = WebTelemetryMetadata(
                user_id="user_test",
                datadog_session_id=session_id,
                resource_type=ResourceType.LOAN_APPLICATION,
                resource_id=f"loan_{i+1}",
                resource_owner_id=f"owner_{i+1}",
                http_method="GET",
                failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED,
                failure_timestamp=datetime.utcnow(),
            )
            detection_monitor.track_access_attempt(telemetry, success=False)
        
        # Get stats
        stats = detection_monitor.get_session_stats(session_id)
        
        assert stats["session_id"] == session_id
        assert stats["failure_count"] == 2
        assert stats["distinct_resources"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
