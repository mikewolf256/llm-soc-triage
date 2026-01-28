"""
Detection middleware orchestration for ownership-aware IDOR detection.

This module ties together all detection components into a cohesive flow:

Flow:
    1. Extract RUM telemetry from request headers (RUMCorrelator)
    2. Lookup resource ownership from DB/cache (OwnershipTracker)
    3. Make authorization decision
    4. Track access patterns (IdentityAssetMonitor)
    5. Detect IDOR patterns
    6. Send high-confidence alerts to SOAR
    7. Use LLM for context on edge cases

Architecture:
    This sits AFTER PII scrubbing but BEFORE the LLM triage call.
    Deterministic rule logic runs first, LLM only invoked for context
    on ambiguous patterns (reduces cost, improves latency).
"""

from typing import Optional, Callable
from datetime import datetime
import logging

from fastapi import Request, Response
from .rum_correlator import RUMCorrelator
from .ownership_tracker import OwnershipTracker
from .detection_monitor import IdentityAssetMonitor
from .schema.web_telemetry import (
    WebTelemetryMetadata,
    AccessAttemptResult,
    IDORDetectionEvent,
    FailureType,
    ResourceType,
)


logger = logging.getLogger(__name__)


class DetectionMiddleware:
    """
    Orchestrates IDOR detection across request lifecycle.
    
    Usage (FastAPI dependency injection):
        from fastapi import Depends
        from core.redis_manager import get_redis_client
        from core.detection_middleware import get_detection_middleware
        
        @app.get("/consumer/loan_applications/{loan_id}")
        async def get_loan(
            loan_id: str,
            request: Request,
            detection: DetectionMiddleware = Depends(get_detection_middleware)
        ):
            # Your authorization logic
            loan = db.get_loan(loan_id)
            user_id = get_current_user_id(request)
            
            if loan.owner_id != user_id:
                # Track IDOR attempt
                await detection.track_unauthorized_access(
                    request,
                    resource_id=loan_id,
                    resource_type=ResourceType.LOAN_APPLICATION,
                    resource_owner_id=loan.owner_id,
                    failure_type=FailureType.AUTHZ_OWNERSHIP_DENIED
                )
                raise HTTPException(403, "Access denied")
            
            # Record successful ownership
            await detection.track_authorized_access(
                request,
                resource_id=loan_id,
                resource_type=ResourceType.LOAN_APPLICATION
            )
            
            return loan
    
    Usage (Middleware integration):
        # Add to FastAPI app
        from core.detection_middleware import DetectionMiddleware
        
        detection = get_detection_middleware()
        app.middleware("http")(detection.http_middleware)
    """
    
    def __init__(
        self,
        rum_correlator: RUMCorrelator,
        ownership_tracker: OwnershipTracker,
        identity_monitor: IdentityAssetMonitor,
        soar_callback: Optional[Callable] = None,
        llm_context_callback: Optional[Callable] = None,
    ):
        """
        Initialize detection middleware.
        
        Args:
            rum_correlator: Telemetry extraction engine
            ownership_tracker: Resource ownership state manager
            identity_monitor: IDOR pattern detection engine
            soar_callback: Optional callback for SOAR alert (async)
            llm_context_callback: Optional callback for LLM context analysis
        """
        self.rum = rum_correlator
        self.ownership = ownership_tracker
        self.monitor = identity_monitor
        self.soar_callback = soar_callback
        self.llm_callback = llm_context_callback
    
    async def track_authorized_access(
        self,
        request: Request,
        resource_id: str,
        resource_type: ResourceType,
        user_id: Optional[str] = None,
    ) -> None:
        """
        Track successful authorized access to a resource.
        
        Records ownership for future IDOR detection.
        
        Args:
            request: FastAPI request
            resource_id: Resource that was accessed
            resource_type: Type of resource
            user_id: Optional explicit user ID (overrides header extraction)
        """
        try:
            telemetry = self.rum.extract_telemetry(
                request,
                resource_id=resource_id,
                resource_type=resource_type,
            )
            
            # Override user_id if provided
            if user_id:
                telemetry.user_id = user_id
            
            # Track successful access (records ownership)
            result, event = self.monitor.track_access_attempt(
                telemetry,
                success=True
            )
            
            logger.debug(
                f"Tracked authorized access: user={telemetry.user_id}, "
                f"resource={resource_type.value}:{resource_id}"
            )
        
        except Exception as e:
            logger.error(f"Error tracking authorized access: {e}", exc_info=True)
    
    async def track_unauthorized_access(
        self,
        request: Request,
        resource_id: str,
        resource_type: ResourceType,
        resource_owner_id: Optional[str] = None,
        failure_type: FailureType = FailureType.AUTHZ_OWNERSHIP_DENIED,
        user_id: Optional[str] = None,
    ) -> tuple[AccessAttemptResult, Optional[IDORDetectionEvent]]:
        """
        Track unauthorized access attempt (403 response).
        
        Detects IDOR patterns and triggers alerts when necessary.
        
        Args:
            request: FastAPI request
            resource_id: Resource that was denied
            resource_type: Type of resource
            resource_owner_id: Who owns the resource (for ownership check)
            failure_type: Type of authorization failure
            user_id: Optional explicit user ID
        
        Returns:
            tuple: (severity, Optional[detection_event])
        
        Side Effects:
            - Sends SOAR alert if CRITICAL_IDOR_ATTACK detected
            - Invokes LLM for context on ALERT_MEDIUM patterns
        """
        try:
            telemetry = self.rum.extract_telemetry(
                request,
                resource_id=resource_id,
                resource_type=resource_type,
                resource_owner_id=resource_owner_id,
                failure_type=failure_type,
            )
            
            # Override user_id if provided
            if user_id:
                telemetry.user_id = user_id
            
            # Track failure and detect patterns
            result, event = self.monitor.track_access_attempt(
                telemetry,
                success=False
            )
            
            logger.info(
                f"Tracked unauthorized access: user={telemetry.user_id}, "
                f"resource={resource_type.value}:{resource_id}, "
                f"severity={result.value}"
            )
            
            # Handle detection results
            if result == AccessAttemptResult.CRITICAL_IDOR_ATTACK:
                logger.critical(
                    f"CRITICAL IDOR ATTACK DETECTED: {event.event_id} - "
                    f"user={event.user_id}, {event.distinct_resources_accessed} "
                    f"resources, sequential={event.is_sequential}"
                )
                
                # Send to SOAR immediately
                if self.soar_callback:
                    await self._send_to_soar(event)
                else:
                    logger.warning("No SOAR callback configured - alert NOT sent!")
            
            elif result == AccessAttemptResult.ALERT_MEDIUM:
                logger.warning(
                    f"MEDIUM confidence IDOR pattern: user={telemetry.user_id}, "
                    f"session={telemetry.get_session_identifier()}"
                )
                
                # Use LLM for context analysis on ambiguous patterns
                if self.llm_callback and event:
                    await self._analyze_with_llm(event, telemetry)
            
            return result, event
        
        except Exception as e:
            logger.error(f"Error tracking unauthorized access: {e}", exc_info=True)
            return AccessAttemptResult.LOG_ONLY, None
    
    async def _send_to_soar(self, event: IDORDetectionEvent):
        """
        Send detection event to SOAR system.
        
        This is the "Auto-Hold" action for high-confidence attacks.
        """
        try:
            if self.soar_callback:
                await self.soar_callback(event)
                logger.info(f"Sent IDOR event {event.event_id} to SOAR")
            else:
                logger.warning(f"SOAR callback not configured for event {event.event_id}")
        except Exception as e:
            logger.error(f"Failed to send event to SOAR: {e}", exc_info=True)
    
    async def _analyze_with_llm(
        self,
        event: IDORDetectionEvent,
        telemetry: WebTelemetryMetadata,
    ):
        """
        Use LLM to add business context for ambiguous patterns.
        
        LLM analyzes:
        - Is this user a known pentester/QA?
        - Recent deployment changes affecting ownership?
        - Historical behavior patterns?
        - Legitimate reason for multi-resource access?
        
        This prevents false positives while maintaining zero false negatives.
        """
        try:
            if self.llm_callback:
                context = await self.llm_callback(event, telemetry)
                logger.info(
                    f"LLM context analysis for {event.event_id}: {context.get('verdict')}"
                )
                
                # If LLM says it's actually critical, escalate to SOAR
                if context.get('verdict') == 'TRUE_POSITIVE' and context.get('confidence', 0) > 0.85:
                    logger.warning(f"LLM escalating {event.event_id} to CRITICAL")
                    await self._send_to_soar(event)
        
        except Exception as e:
            logger.error(f"LLM context analysis failed: {e}", exc_info=True)
    
    async def http_middleware(self, request: Request, call_next):
        """
        FastAPI HTTP middleware for automatic detection.
        
        Wraps requests to automatically detect IDOR patterns based
        on response status codes.
        
        Usage:
            app = FastAPI()
            detection = get_detection_middleware()
            app.middleware("http")(detection.http_middleware)
        
        Note:
            This is an alternative to explicit track_* calls.
            Use one approach or the other, not both.
        """
        # Extract telemetry before request
        try:
            telemetry = self.rum.extract_telemetry(request)
        except Exception as e:
            logger.error(f"Failed to extract telemetry: {e}")
            # Continue without detection
            return await call_next(request)
        
        # Process request
        response: Response = await call_next(request)
        
        # Check response status
        if response.status_code == 200:
            # Successful access - record ownership
            try:
                _, _ = self.monitor.track_access_attempt(telemetry, success=True)
            except Exception as e:
                logger.error(f"Error tracking success in middleware: {e}")
        
        elif response.status_code == 403:
            # Unauthorized - check for IDOR pattern
            try:
                result, event = self.monitor.track_access_attempt(
                    telemetry,
                    success=False
                )
                
                # Handle critical alerts
                if result == AccessAttemptResult.CRITICAL_IDOR_ATTACK and event:
                    if self.soar_callback:
                        await self._send_to_soar(event)
            
            except Exception as e:
                logger.error(f"Error tracking failure in middleware: {e}")
        
        return response
    
    def get_user_stats(self, user_id: str) -> dict:
        """
        Get statistics for a user's ownership and access patterns.
        
        Useful for debugging and analytics dashboard.
        """
        try:
            owned_count = self.ownership.get_ownership_count(user_id)
            owned_resources = self.ownership.get_owned_resources(user_id)
            
            return {
                "user_id": user_id,
                "owned_resources_count": owned_count,
                "owned_resources": list(owned_resources)[:10],  # First 10 for preview
            }
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {"error": str(e)}
    
    def get_session_stats(self, session_id: str) -> dict:
        """
        Get statistics for a session's access patterns.
        
        Useful for live monitoring and incident investigation.
        """
        try:
            return self.monitor.get_session_stats(session_id)
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return {"error": str(e)}


# Global singleton for dependency injection
_detection_middleware: Optional[DetectionMiddleware] = None


def get_detection_middleware() -> DetectionMiddleware:
    """
    Get global detection middleware singleton.
    
    Initializes all components with default configuration.
    
    Usage:
        from fastapi import Depends
        from core.detection_middleware import get_detection_middleware
        
        @app.get("/api/resource/{id}")
        async def get_resource(
            id: str,
            detection: DetectionMiddleware = Depends(get_detection_middleware)
        ):
            # Your endpoint logic
            ...
    """
    global _detection_middleware
    
    if _detection_middleware is None:
        from .redis_manager import get_redis_client
        
        # Initialize components
        redis_client = get_redis_client()
        rum_correlator = RUMCorrelator()
        ownership_tracker = OwnershipTracker(redis_client)
        identity_monitor = IdentityAssetMonitor(redis_client, ownership_tracker)
        
        _detection_middleware = DetectionMiddleware(
            rum_correlator=rum_correlator,
            ownership_tracker=ownership_tracker,
            identity_monitor=identity_monitor,
            # SOAR and LLM callbacks can be configured later
        )
    
    return _detection_middleware


def configure_soar_callback(callback: Callable):
    """
    Configure SOAR alert callback.
    
    Args:
        callback: Async function that receives IDORDetectionEvent
    
    Example:
        async def send_to_soar(event: IDORDetectionEvent):
            # Send to your SOAR platform
            response = await soar_api.create_incident(event.dict())
        
        configure_soar_callback(send_to_soar)
    """
    global _detection_middleware
    if _detection_middleware:
        _detection_middleware.soar_callback = callback
        logger.info("SOAR callback configured")
    else:
        logger.warning("Detection middleware not initialized yet")


def configure_llm_callback(callback: Callable):
    """
    Configure LLM context analysis callback.
    
    Args:
        callback: Async function that receives event and telemetry,
                  returns context dict
    
    Example:
        async def analyze_with_claude(
            event: IDORDetectionEvent,
            telemetry: WebTelemetryMetadata
        ) -> dict:
            # Use existing LLM triage system
            prompt = build_idor_context_prompt(event, telemetry)
            response = await claude_api.analyze(prompt)
            return response
        
        configure_llm_callback(analyze_with_claude)
    """
    global _detection_middleware
    if _detection_middleware:
        _detection_middleware.llm_callback = callback
        logger.info("LLM callback configured")
    else:
        logger.warning("Detection middleware not initialized yet")
