"""
Ownership tracking for resource access patterns.

Maintains Redis-backed mappings of user→owned resources to enable
ownership-aware IDOR detection.

Key Insight:
    A user accessing their own 10 loans = Legitimate
    A user accessing 3 OTHER users' loans = IDOR Attack

Redis Data Structures:
    user:{user_id}:owned_loans = Set[loan_id_1, loan_id_2, ...]
    loan:{loan_id}:owner = user_id
    
TTL Strategy:
    24 hours default - balances memory usage with detection accuracy.
    Active users refresh their ownership mapping on each successful access.
"""

import redis
from typing import Set, Optional
import logging
from datetime import timedelta


logger = logging.getLogger(__name__)


class OwnershipTracker:
    """
    Tracks resource ownership for IDOR detection.
    
    Usage:
        from core.redis_manager import get_redis_client
        from core.ownership_tracker import OwnershipTracker
        
        tracker = OwnershipTracker(get_redis_client())
        
        # Record ownership on successful access
        tracker.record_ownership("user_789", "loan_4395668")
        
        # Check ownership before flagging as IDOR
        if not tracker.is_owner("user_789", "loan_4395669"):
            # User attempting to access someone else's loan
            monitor.track_potential_idor(...)
    
    Redis Key Schema:
        - user:{user_id}:owned_loans → Set of loan IDs
        - loan:{loan_id}:owner → Owner user ID
    
    Performance:
        - record_ownership: O(1) SADD + O(1) SET = ~2ms
        - is_owner: O(1) SISMEMBER = ~1ms
        - get_owned_loans: O(n) SMEMBERS = ~5ms for 100 loans
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        default_ttl_seconds: int = 86400,  # 24 hours
        key_prefix: str = ""
    ):
        """
        Initialize ownership tracker.
        
        Args:
            redis_client: Redis client from RedisManager
            default_ttl_seconds: Default TTL for ownership records (24h)
            key_prefix: Optional key prefix for multi-tenancy
        """
        self.redis = redis_client
        self.default_ttl = default_ttl_seconds
        self.key_prefix = key_prefix
    
    def _user_loans_key(self, user_id: str) -> str:
        """Generate Redis key for user's owned loans set."""
        return f"{self.key_prefix}user:{user_id}:owned_loans"
    
    def _loan_owner_key(self, loan_id: str) -> str:
        """Generate Redis key for loan owner mapping."""
        return f"{self.key_prefix}loan:{loan_id}:owner"
    
    def record_ownership(
        self,
        user_id: str,
        resource_id: str,
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Record that a user owns a resource.
        
        Called when:
        1. User successfully creates a resource (loan application)
        2. User successfully accesses a resource (200 OK)
        3. Authorization system confirms ownership
        
        Args:
            user_id: User who owns the resource
            resource_id: Resource identifier (e.g., loan_4395668)
            ttl_seconds: Optional custom TTL (defaults to 24h)
        
        Returns:
            bool: True if successfully recorded
        
        Example:
            # User creates loan
            tracker.record_ownership("user_789", "loan_4395668")
            
            # Later, user accesses their loan (200 OK)
            tracker.record_ownership("user_789", "loan_4395668")  # Refreshes TTL
        """
        ttl = ttl_seconds or self.default_ttl
        
        try:
            # Add to user's owned set
            user_key = self._user_loans_key(user_id)
            self.redis.sadd(user_key, resource_id)
            self.redis.expire(user_key, ttl)
            
            # Set reverse lookup (loan → owner)
            owner_key = self._loan_owner_key(resource_id)
            self.redis.setex(owner_key, ttl, user_id)
            
            logger.debug(
                f"Recorded ownership: user={user_id}, resource={resource_id}, ttl={ttl}s"
            )
            return True
        
        except redis.RedisError as e:
            logger.error(f"Failed to record ownership: {e}")
            return False
    
    def is_owner(self, user_id: str, resource_id: str) -> bool:
        """
        Check if user owns a specific resource.
        
        Fast O(1) check using Redis SISMEMBER.
        
        Args:
            user_id: User to check
            resource_id: Resource to check
        
        Returns:
            bool: True if user owns resource, False otherwise
        
        Example:
            if tracker.is_owner("user_789", "loan_4395668"):
                # Legitimate access
            else:
                # Potential IDOR - accessing someone else's loan
        """
        try:
            user_key = self._user_loans_key(user_id)
            return bool(self.redis.sismember(user_key, resource_id))
        except redis.RedisError as e:
            logger.error(f"Failed to check ownership: {e}")
            # Conservative: assume not owner on error
            return False
    
    def get_owned_resources(self, user_id: str) -> Set[str]:
        """
        Get all resources owned by a user.
        
        Args:
            user_id: User ID to query
        
        Returns:
            Set[str]: Set of resource IDs owned by user
        
        Example:
            loans = tracker.get_owned_resources("user_789")
            # Returns: {"loan_4395668", "loan_4395720", ...}
        """
        try:
            user_key = self._user_loans_key(user_id)
            resources = self.redis.smembers(user_key)
            
            # Handle both bytes and string responses
            if resources and isinstance(next(iter(resources)), bytes):
                return {r.decode() for r in resources}
            return set(resources)
        
        except redis.RedisError as e:
            logger.error(f"Failed to get owned resources: {e}")
            return set()
    
    def get_resource_owner(self, resource_id: str) -> Optional[str]:
        """
        Get the owner of a specific resource.
        
        Reverse lookup: loan → user
        
        Args:
            resource_id: Resource to query
        
        Returns:
            Optional[str]: Owner user ID, or None if unknown
        
        Example:
            owner = tracker.get_resource_owner("loan_4395668")
            if owner == "user_456":
                # Loan belongs to user_456
        """
        try:
            owner_key = self._loan_owner_key(resource_id)
            owner = self.redis.get(owner_key)
            
            if owner is None:
                return None
            
            # Handle bytes response
            if isinstance(owner, bytes):
                return owner.decode()
            return owner
        
        except redis.RedisError as e:
            logger.error(f"Failed to get resource owner: {e}")
            return None
    
    def remove_ownership(self, user_id: str, resource_id: str) -> bool:
        """
        Remove ownership record (e.g., loan deleted or transferred).
        
        Args:
            user_id: User who owned the resource
            resource_id: Resource to remove
        
        Returns:
            bool: True if successfully removed
        """
        try:
            # Remove from user's set
            user_key = self._user_loans_key(user_id)
            self.redis.srem(user_key, resource_id)
            
            # Remove reverse lookup
            owner_key = self._loan_owner_key(resource_id)
            self.redis.delete(owner_key)
            
            logger.debug(
                f"Removed ownership: user={user_id}, resource={resource_id}"
            )
            return True
        
        except redis.RedisError as e:
            logger.error(f"Failed to remove ownership: {e}")
            return False
    
    def get_ownership_count(self, user_id: str) -> int:
        """
        Get count of resources owned by user.
        
        Useful for analytics and anomaly detection.
        
        Args:
            user_id: User to query
        
        Returns:
            int: Number of resources owned
        """
        try:
            user_key = self._user_loans_key(user_id)
            return self.redis.scard(user_key)
        except redis.RedisError as e:
            logger.error(f"Failed to get ownership count: {e}")
            return 0
    
    def bulk_record_ownership(
        self,
        user_id: str,
        resource_ids: list[str],
        ttl_seconds: Optional[int] = None
    ) -> int:
        """
        Record ownership of multiple resources (batch operation).
        
        Useful for initial sync or bulk imports.
        
        Args:
            user_id: User who owns the resources
            resource_ids: List of resource IDs
            ttl_seconds: Optional custom TTL
        
        Returns:
            int: Number of successfully recorded ownerships
        """
        ttl = ttl_seconds or self.default_ttl
        success_count = 0
        
        try:
            # Use Redis pipeline for efficiency
            pipe = self.redis.pipeline()
            
            user_key = self._user_loans_key(user_id)
            
            # Add all to user's set
            for resource_id in resource_ids:
                pipe.sadd(user_key, resource_id)
                # Set reverse lookups
                owner_key = self._loan_owner_key(resource_id)
                pipe.setex(owner_key, ttl, user_id)
            
            # Set TTL on user's set
            pipe.expire(user_key, ttl)
            
            # Execute pipeline
            pipe.execute()
            
            success_count = len(resource_ids)
            logger.info(
                f"Bulk recorded {success_count} ownerships for user={user_id}"
            )
        
        except redis.RedisError as e:
            logger.error(f"Failed bulk ownership recording: {e}")
        
        return success_count
    
    def clear_user_ownership(self, user_id: str) -> bool:
        """
        Clear all ownership records for a user.
        
        Useful for account deletion or testing.
        
        Args:
            user_id: User whose ownership to clear
        
        Returns:
            bool: True if successfully cleared
        """
        try:
            # Get all owned resources first
            resources = self.get_owned_resources(user_id)
            
            # Delete reverse lookups
            pipe = self.redis.pipeline()
            for resource_id in resources:
                owner_key = self._loan_owner_key(resource_id)
                pipe.delete(owner_key)
            
            # Delete user's owned set
            user_key = self._user_loans_key(user_id)
            pipe.delete(user_key)
            
            pipe.execute()
            
            logger.info(
                f"Cleared {len(resources)} ownership records for user={user_id}"
            )
            return True
        
        except redis.RedisError as e:
            logger.error(f"Failed to clear user ownership: {e}")
            return False
