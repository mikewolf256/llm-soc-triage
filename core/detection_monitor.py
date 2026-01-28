"""
Identity-Asset Monitor for ownership-aware IDOR detection.

Core detection engine that distinguishes between:
- Legitimate: User accessing their own resources
- Attack: User attempting to enumerate OTHER users' resources

Detection Strategy:
    Traditional: "User accessed 10 resources → ALERT"
    Ownership-Aware: "User accessed 3 OTHER USERS' resources → ALERT"

This eliminates false positives from legitimate multi-resource users while
maintaining high sensitivity to actual IDOR enumeration attacks.
"""

import redis
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import logging

from .ownership_tracker import OwnershipTracker
from .schema.web_telemetry import (
    WebTelemetryMetadata,
    AccessAttemptResult,
    IDORDetectionEvent,
)


logger = logging.getLogger(__name__)


class IdentityAssetMonitor:
    """
    Ownership-aware IDOR detection monitor.
    
    Key Innovation:
        Only tracks authorization failures on OTHER users' resources.
        Failures on own resources are logged but not counted toward
        enumeration patterns (they're legitimate retries/bugs).
    
    Redis Key Structure:
        session:{session_id}:other_loan_failures = SortedSet[
            {loan_id, owner, ts, ...} sorted by timestamp
        ]
        
        TTL: 60 seconds (sliding window for real-time detection)
    
    Detection Logic:
        1. User accesses resource → Check ownership
        2. If 200 OK → Record ownership, no tracking needed
        3. If 403 on OWN resource → Log only (bug, not attack)
        4. If 403 on OTHER resource → Track for IDOR pattern
        5. If 3+ distinct OTHER resources in 60s → Alert
        6. If sequential IDs → High confidence CRITICAL alert
    
    Usage:
        from core.redis_manager import get_redis_client
        from core.ownership_tracker import OwnershipTracker
        from core.detection_monitor import IdentityAssetMonitor
        
        redis_client = get_redis_client()
        ownership = OwnershipTracker(redis_client)
        monitor = IdentityAssetMonitor(redis_client, ownership)
        
        # On access attempt
        result = monitor.track_access_attempt(telemetry, success=False)
        
        if result.severity == AccessAttemptResult.CRITICAL_IDOR_ATTACK:
            # Send to SOAR for incident response
            soar.create_incident(result.to_dict())
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        ownership_tracker: OwnershipTracker,
        threshold: int = 3,  # Min distinct OTHER-user resources
        window_seconds: int = 60,  # Detection time window
        sequential_gap_threshold: int = 10,  # Max gap for "sequential" IDs
    ):
        """
        Initialize IDOR detection monitor.
        
        Args:
            redis_client: Redis client for state tracking
            ownership_tracker: Ownership tracker instance
            threshold: Minimum distinct OTHER-user resources to trigger alert
            window_seconds: Time window for pattern detection
            sequential_gap_threshold: Max ID gap to consider "sequential"
        """
        self.redis = redis_client
        self.ownership = ownership_tracker
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.sequential_gap = sequential_gap_threshold
    
    def _session_failures_key(self, session_id: str) -> str:
        """Generate Redis key for session's OTHER-loan failures."""
        return f"session:{session_id}:other_loan_failures"
    
    def track_access_attempt(
        self,
        telemetry: WebTelemetryMetadata,
        success: bool,
    ) -> tuple[AccessAttemptResult, Optional[IDORDetectionEvent]]:
        """
        Track resource access attempt and detect IDOR patterns.
        
        Core Decision Tree:
        1. Success (200) → Record ownership, return LEGITIMATE_ACCESS
        2. Failure on OWN resource → Log only, return LOG_ONLY
        3. Failure on OTHER resource → Track and analyze for IDOR
        
        Args:
            telemetry: Request telemetry with user, resource, session data
            success: Whether access was granted (200 vs 403)
        
        Returns:
            tuple: (AccessAttemptResult, Optional[IDORDetectionEvent])
                - Result: Severity level (LOG_ONLY → CRITICAL_IDOR_ATTACK)
                - Event: Detection event if pattern found, else None
        
        Example:
            telemetry = WebTelemetryMetadata(
                user_id="user_789",
                resource_id="loan_4395669",
                resource_owner_id="user_456",  # Not user_789!
                ...
            )
            
            result, event = monitor.track_access_attempt(telemetry, success=False)
            
            if result == AccessAttemptResult.CRITICAL_IDOR_ATTACK:
                soar.alert(event)
        """
        session_id = telemetry.get_session_identifier()
        
        if not session_id:
            logger.warning("No session identifier in telemetry, cannot track")
            return AccessAttemptResult.LOG_ONLY, None
        
        # Case 1: Successful access → Record ownership
        if success:
            self.ownership.record_ownership(
                telemetry.user_id,
                telemetry.resource_id
            )
            return AccessAttemptResult.LEGITIMATE_ACCESS, None
        
        # Case 2: Failure - check if accessing OWN resource
        is_own = telemetry.is_accessing_own_resource()
        
        if is_own is None:
            # Ownership unknown - check with tracker
            is_own = self.ownership.is_owner(
                telemetry.user_id,
                telemetry.resource_id
            )
        
        if is_own:
            # User failed to access their OWN resource
            # This is likely an infrastructure/bug issue, not an attack
            logger.info(
                f"User {telemetry.user_id} failed to access own resource "
                f"{telemetry.resource_id} - potential backend bug"
            )
            return AccessAttemptResult.LOG_ONLY, None
        
        # Case 3: Failure on OTHER user's resource - potential IDOR
        return self._track_other_user_failure(telemetry, session_id)
    
    def _track_other_user_failure(
        self,
        telemetry: WebTelemetryMetadata,
        session_id: str,
    ) -> tuple[AccessAttemptResult, Optional[IDORDetectionEvent]]:
        """
        Track failure on OTHER user's resource and detect patterns.
        
        This is where IDOR detection happens.
        """
        now = datetime.utcnow().timestamp()
        session_key = self._session_failures_key(session_id)
        
        # Build failure record
        failure_data = {
            "resource_id": telemetry.resource_id,
            "resource_type": telemetry.resource_type.value,
            "resource_owner": telemetry.resource_owner_id,
            "attempted_by": telemetry.user_id,
            "timestamp": now,
            "failure_type": telemetry.failure_type.value if telemetry.failure_type else "unknown",
            "request_path": telemetry.request_path,
        }
        
        try:
            # Store in Redis sorted set (score = timestamp)
            self.redis.zadd(
                session_key,
                {json.dumps(failure_data): now}
            )
            
            # Set TTL on key (sliding window)
            self.redis.expire(session_key, self.window_seconds)
            
            # Analyze recent failures within window
            cutoff = now - self.window_seconds
            recent_raw = self.redis.zrangebyscore(session_key, cutoff, now)
            
            # Parse failures
            recent_failures = [
                json.loads(f.decode() if isinstance(f, bytes) else f)
                for f in recent_raw
            ]
            
            # Analyze pattern
            return self._analyze_failure_pattern(
                telemetry,
                session_id,
                recent_failures
            )
        
        except redis.RedisError as e:
            logger.error(f"Redis error tracking failure: {e}")
            return AccessAttemptResult.LOG_ONLY, None
    
    def _analyze_failure_pattern(
        self,
        telemetry: WebTelemetryMetadata,
        session_id: str,
        failures: List[Dict[str, Any]],
    ) -> tuple[AccessAttemptResult, Optional[IDORDetectionEvent]]:
        """
        Analyze failure pattern for IDOR indicators.
        
        Detection Thresholds:
        - 1 failure: LOG_ONLY (might be typo/bookmark)
        - 2 failures: ALERT_LOW (worth watching)
        - 3+ failures, non-sequential: ALERT_MEDIUM
        - 3+ failures, sequential: CRITICAL_IDOR_ATTACK
        """
        if not failures:
            return AccessAttemptResult.LOG_ONLY, None
        
        # Count distinct OTHER-user resources accessed
        distinct_resources = set(f['resource_id'] for f in failures)
        distinct_count = len(distinct_resources)
        
        logger.info(
            f"Session {session_id}: {distinct_count} distinct OTHER-user "
            f"resources accessed in {self.window_seconds}s"
        )
        
        # Single failure - log only
        if distinct_count < 2:
            return AccessAttemptResult.LOG_ONLY, None
        
        # 2 failures - low confidence alert
        if distinct_count == 2:
            return AccessAttemptResult.ALERT_LOW, None
        
        # 3+ failures - check for sequential pattern
        is_sequential, numeric_ids = self._check_sequential_pattern(distinct_resources)
        
        if distinct_count >= self.threshold:
            if is_sequential:
                # High confidence IDOR attack
                severity = AccessAttemptResult.CRITICAL_IDOR_ATTACK
            else:
                # Medium confidence - many resources but not sequential
                severity = AccessAttemptResult.ALERT_MEDIUM
            
            # Generate detection event
            event = self._create_detection_event(
                telemetry,
                session_id,
                failures,
                severity,
                is_sequential,
                distinct_count
            )
            
            logger.warning(
                f"IDOR pattern detected: {severity.value} - "
                f"{distinct_count} resources, sequential={is_sequential}"
            )
            
            return severity, event
        
        # 3+ but below threshold
        return AccessAttemptResult.ALERT_MEDIUM, None
    
    def _check_sequential_pattern(
        self,
        resource_ids: set[str],
    ) -> tuple[bool, List[int]]:
        """
        Check if resource IDs follow a sequential pattern.
        
        Sequential IDs are a strong indicator of automated enumeration.
        
        Args:
            resource_ids: Set of resource ID strings
        
        Returns:
            tuple: (is_sequential, numeric_ids)
                - is_sequential: True if IDs are within gap threshold
                - numeric_ids: Sorted list of numeric IDs (empty if not numeric)
        
        Example:
            IDs = ["4395668", "4395669", "4395670"]
            → gaps = [1, 1], avg_gap = 1, is_sequential = True
            
            IDs = ["4395668", "4395720", "4395999"]
            → gaps = [52, 279], avg_gap = 165, is_sequential = False
        """
        # Extract numeric IDs
        numeric_ids = []
        for rid in resource_ids:
            try:
                numeric_ids.append(int(rid))
            except ValueError:
                # Non-numeric ID, can't check sequential
                continue
        
        if len(numeric_ids) < 3:
            # Need at least 3 numeric IDs to determine pattern
            return False, numeric_ids
        
        # Sort and calculate gaps
        numeric_ids.sort()
        gaps = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
        
        # Calculate average gap
        avg_gap = sum(gaps) / len(gaps)
        
        # Sequential if average gap is within threshold
        is_sequential = avg_gap <= self.sequential_gap
        
        logger.debug(
            f"Sequential check: IDs={numeric_ids}, gaps={gaps}, "
            f"avg_gap={avg_gap:.1f}, threshold={self.sequential_gap}, "
            f"is_sequential={is_sequential}"
        )
        
        return is_sequential, numeric_ids
    
    def _create_detection_event(
        self,
        telemetry: WebTelemetryMetadata,
        session_id: str,
        failures: List[Dict[str, Any]],
        severity: AccessAttemptResult,
        is_sequential: bool,
        distinct_count: int,
    ) -> IDORDetectionEvent:
        """
        Create structured detection event for SOAR ingestion.
        """
        # Calculate time window
        timestamps = [f['timestamp'] for f in failures]
        time_span = max(timestamps) - min(timestamps)
        
        # Extract evidence
        failed_resources = [f['resource_id'] for f in failures]
        resource_owners = list(set(f['resource_owner'] for f in failures if f.get('resource_owner')))
        
        # Generate event ID
        event_id = f"idor_evt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        return IDORDetectionEvent(
            event_id=event_id,
            detection_timestamp=datetime.utcnow(),
            user_id=telemetry.user_id,
            session_id=session_id,
            severity=severity,
            distinct_resources_accessed=distinct_count,
            is_sequential=is_sequential,
            time_window_seconds=int(time_span),
            failed_resources=failed_resources,
            resource_owners=resource_owners,
            telemetry_snapshot=telemetry,
        )
    
    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """
        Get statistics for a session's failure pattern.
        
        Useful for debugging and analytics.
        
        Args:
            session_id: Session to query
        
        Returns:
            dict: Session statistics
        """
        session_key = self._session_failures_key(session_id)
        
        try:
            # Get all failures in current window
            now = datetime.utcnow().timestamp()
            cutoff = now - self.window_seconds
            recent_raw = self.redis.zrangebyscore(session_key, cutoff, now)
            
            if not recent_raw:
                return {
                    "session_id": session_id,
                    "failure_count": 0,
                    "distinct_resources": 0,
                    "window_seconds": self.window_seconds,
                }
            
            failures = [
                json.loads(f.decode() if isinstance(f, bytes) else f)
                for f in recent_raw
            ]
            
            distinct_resources = set(f['resource_id'] for f in failures)
            distinct_owners = set(f.get('resource_owner') for f in failures if f.get('resource_owner'))
            
            timestamps = [f['timestamp'] for f in failures]
            time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
            
            return {
                "session_id": session_id,
                "failure_count": len(failures),
                "distinct_resources": len(distinct_resources),
                "distinct_owners": len(distinct_owners),
                "time_span_seconds": time_span,
                "window_seconds": self.window_seconds,
                "first_failure": datetime.fromtimestamp(min(timestamps)).isoformat(),
                "last_failure": datetime.fromtimestamp(max(timestamps)).isoformat(),
            }
        
        except redis.RedisError as e:
            logger.error(f"Failed to get session stats: {e}")
            return {"error": str(e)}
    
    def clear_session(self, session_id: str) -> bool:
        """
        Clear failure tracking for a session.
        
        Useful for testing or manual incident resolution.
        
        Args:
            session_id: Session to clear
        
        Returns:
            bool: True if successfully cleared
        """
        session_key = self._session_failures_key(session_id)
        try:
            self.redis.delete(session_key)
            logger.info(f"Cleared failure tracking for session {session_id}")
            return True
        except redis.RedisError as e:
            logger.error(f"Failed to clear session: {e}")
            return False
