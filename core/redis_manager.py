"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Redis connection manager with graceful failover to in-memory cache.

Provides resilient session state management for IDOR detection:
- Production: Connects to Redis (shared state across instances)
- Development: Uses fakeredis (in-memory, no external dependencies)
- Failover: Automatically degrades to in-memory if Redis unavailable

Connection Modes:
1. PRODUCTION: redis://host:6379/0
2. DEV_LOCAL: fakeredis (in-memory, single instance)
3. FAILOVER: Attempts Redis, falls back to fakeredis on failure

Architecture Decision:
Redis is used for stateful tracking of ownership and failure patterns.
For ephemeral PoC/dev, fakeredis provides identical API without infrastructure.
"""

import redis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError
import fakeredis
from typing import Optional
import logging
import os
from enum import Enum


logger = logging.getLogger(__name__)


class RedisMode(str, Enum):
    """Redis connection modes"""
    PRODUCTION = "production"  # Real Redis server
    DEV_LOCAL = "dev_local"  # fakeredis (in-memory)
    FAILOVER = "failover"  # Attempt Redis, fallback to fakeredis


class RedisManager:
    """
    Manages Redis connections with automatic failover.
    
    Usage:
        # In production (with Redis server)
        redis_mgr = RedisManager(mode=RedisMode.PRODUCTION)
        client = redis_mgr.get_client()
        
        # In development (no Redis server)
        redis_mgr = RedisManager(mode=RedisMode.DEV_LOCAL)
        client = redis_mgr.get_client()  # Uses fakeredis
        
        # Automatic failover (recommended)
        redis_mgr = RedisManager(mode=RedisMode.FAILOVER)
        client = redis_mgr.get_client()  # Tries Redis, falls back to fakeredis
    
    Environment Variables:
        REDIS_HOST: Redis server hostname (default: localhost)
        REDIS_PORT: Redis server port (default: 6379)
        REDIS_DB: Redis database number (default: 0)
        REDIS_PASSWORD: Redis password (optional)
        REDIS_MODE: Connection mode (production|dev_local|failover, default: failover)
    """
    
    def __init__(
        self,
        mode: Optional[RedisMode] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: Optional[int] = None,
        password: Optional[str] = None,
        socket_timeout: float = 2.0,
        socket_connect_timeout: float = 2.0,
    ):
        """
        Initialize Redis manager.
        
        Args:
            mode: Connection mode (defaults to env REDIS_MODE or FAILOVER)
            host: Redis host (defaults to env REDIS_HOST or 'localhost')
            port: Redis port (defaults to env REDIS_PORT or 6379)
            db: Redis database (defaults to env REDIS_DB or 0)
            password: Redis password (defaults to env REDIS_PASSWORD or None)
            socket_timeout: Timeout for Redis operations
            socket_connect_timeout: Timeout for initial connection
        """
        # Load from environment or use defaults
        self.mode = mode or RedisMode(os.getenv("REDIS_MODE", "failover"))
        self.host = host or os.getenv("REDIS_HOST", "localhost")
        self.port = port or int(os.getenv("REDIS_PORT", "6379"))
        self.db = db if db is not None else int(os.getenv("REDIS_DB", "0"))
        self.password = password or os.getenv("REDIS_PASSWORD")
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        
        self._client: Optional[redis.Redis] = None
        self._is_fake = False
    
    def get_client(self) -> redis.Redis:
        """
        Get Redis client with appropriate failover logic.
        
        Returns:
            redis.Redis: Connected Redis client (real or fake)
        
        Raises:
            RedisError: Only if mode is PRODUCTION and connection fails
        """
        if self._client is not None:
            return self._client
        
        if self.mode == RedisMode.DEV_LOCAL:
            self._client = self._create_fake_redis()
            logger.info("Using fakeredis (dev mode)")
            return self._client
        
        elif self.mode == RedisMode.PRODUCTION:
            self._client = self._create_real_redis()
            self._test_connection(raise_on_failure=True)
            logger.info(f"Connected to Redis at {self.host}:{self.port}/{self.db}")
            return self._client
        
        else:  # FAILOVER mode
            try:
                self._client = self._create_real_redis()
                self._test_connection(raise_on_failure=True)
                logger.info(f"Connected to Redis at {self.host}:{self.port}/{self.db}")
                return self._client
            except (RedisError, RedisConnectionError) as e:
                logger.warning(
                    f"Redis connection failed ({e}), falling back to in-memory cache"
                )
                self._client = self._create_fake_redis()
                return self._client
    
    def _create_real_redis(self) -> redis.Redis:
        """Create real Redis client."""
        return redis.Redis(
            host=self.host,
            port=self.port,
            db=self.db,
            password=self.password,
            decode_responses=True,
            socket_timeout=self.socket_timeout,
            socket_connect_timeout=self.socket_connect_timeout,
        )
    
    def _create_fake_redis(self) -> redis.Redis:
        """Create fakeredis client (in-memory)."""
        self._is_fake = True
        return fakeredis.FakeRedis(
            decode_responses=True,
            # Simulate Redis server behavior
            version=(7,),  # Mimic Redis 7.x
        )
    
    def _test_connection(self, raise_on_failure: bool = False) -> bool:
        """
        Test Redis connection with PING.
        
        Args:
            raise_on_failure: If True, raise exception on failure
        
        Returns:
            bool: True if connection successful
        
        Raises:
            RedisError: If raise_on_failure=True and connection fails
        """
        try:
            self._client.ping()
            return True
        except (RedisError, RedisConnectionError) as e:
            if raise_on_failure:
                raise
            logger.error(f"Redis health check failed: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check if Redis is connected and healthy."""
        if self._client is None:
            return False
        return self._test_connection(raise_on_failure=False)
    
    def is_using_fake_redis(self) -> bool:
        """Check if using in-memory fakeredis."""
        return self._is_fake
    
    def get_info(self) -> dict:
        """
        Get connection info for monitoring.
        
        Returns:
            dict: Connection metadata
        """
        return {
            "mode": self.mode.value,
            "host": self.host,
            "port": self.port,
            "db": self.db,
            "is_fake": self._is_fake,
            "is_connected": self.is_connected(),
        }
    
    def close(self):
        """Close Redis connection."""
        if self._client:
            try:
                self._client.close()
                logger.info("Redis connection closed")
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {e}")
            finally:
                self._client = None


# Global singleton instance
_redis_manager: Optional[RedisManager] = None


def get_redis_manager() -> RedisManager:
    """
    Get global Redis manager singleton.
    
    Usage:
        from core.redis_manager import get_redis_manager
        
        redis_mgr = get_redis_manager()
        client = redis_mgr.get_client()
        client.set("key", "value")
    
    Returns:
        RedisManager: Configured Redis manager
    """
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisManager()
    return _redis_manager


def get_redis_client() -> redis.Redis:
    """
    Get Redis client directly (convenience function).
    
    Returns:
        redis.Redis: Connected Redis client
    """
    return get_redis_manager().get_client()
