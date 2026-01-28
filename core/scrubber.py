"""
PII Redaction - Keep sensitive data local, only send scrubbed alerts to LLM.

Dual-mode operation:
1. Presidio (preferred): ML-powered entity detection with high accuracy
2. Regex fallback: Pattern matching when Presidio unavailable

This ensures PII scrubbing works in all deployment scenarios while
providing best-in-class detection when dependencies are available.
"""

from typing import Dict, Any, List, Optional
import re
import logging

# Try to import Presidio - graceful fallback if not installed
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

logger = logging.getLogger(__name__)


class PIIScrubber:
    """
    Production-grade PII scrubber with Presidio integration and regex fallback
    
    Features:
    - Automatic mode selection (Presidio preferred, regex fallback)
    - Configurable entity types and confidence thresholds
    - Recursive scrubbing of nested structures
    - Performance logging and metrics
    - Customizable anonymization strategies
    """
    
    def __init__(
        self,
        use_presidio: bool = True,
        min_confidence: float = 0.5,
        language: str = "en"
    ):
        """
        Initialize PII scrubber
        
        Args:
            use_presidio: Attempt to use Presidio if available
            min_confidence: Minimum confidence score for Presidio detections
            language: Language code for Presidio analysis
        """
        self.use_presidio = use_presidio and PRESIDIO_AVAILABLE
        self.min_confidence = min_confidence
        self.language = language
        
        # Initialize Presidio engines if available
        if self.use_presidio:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                logger.info("Presidio engines initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Presidio: {e}. Falling back to regex.")
                self.use_presidio = False
        
        # Regex patterns for fallback
        self.patterns = {
            "EMAIL_ADDRESS": (
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                '[EMAIL_REDACTED]'
            ),
            "IP_ADDRESS": (
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                '[IP_REDACTED]'
            ),
            "US_SSN": (
                r'\b\d{3}-\d{2}-\d{4}\b',
                '[SSN_REDACTED]'
            ),
            "CREDIT_CARD": (
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                '[CC_REDACTED]'
            ),
            "PHONE_NUMBER": (
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                '[PHONE_REDACTED]'
            ),
            "US_PASSPORT": (
                r'\b[A-Z]{1,2}\d{6,9}\b',
                '[PASSPORT_REDACTED]'
            ),
        }
        
        # Entity types to detect with Presidio
        self.presidio_entities = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "US_PASSPORT",
            "IP_ADDRESS",
            "PERSON",
            "LOCATION",
            "DATE_TIME",
            "NRP",  # Nationality/Religion/Political affiliation
            "US_DRIVER_LICENSE",
            "IBAN_CODE",
        ]
    
    def scrub_text_presidio(self, text: str) -> str:
        """
        Scrub PII from text using Presidio
        
        Args:
            text: Text to scrub
            
        Returns:
            Scrubbed text with PII replaced
        """
        if not text or not isinstance(text, str):
            return text
        
        try:
            # Analyze text for PII
            results = self.analyzer.analyze(
                text=text,
                language=self.language,
                entities=self.presidio_entities
            )
            
            # Filter by confidence threshold
            filtered_results = [
                r for r in results if r.score >= self.min_confidence
            ]
            
            # Define anonymization operators
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL_REDACTED]"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE_REDACTED]"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CC_REDACTED]"}),
                "US_SSN": OperatorConfig("replace", {"new_value": "[SSN_REDACTED]"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[IP_REDACTED]"}),
                "PERSON": OperatorConfig("replace", {"new_value": "[NAME_REDACTED]"}),
                "LOCATION": OperatorConfig("replace", {"new_value": "[LOCATION_REDACTED]"}),
            }
            
            # Anonymize
            anonymized = self.anonymizer.anonymize(
                text=text,
                analyzer_results=filtered_results,
                operators=operators
            )
            
            return anonymized.text
            
        except Exception as e:
            logger.error(f"Presidio scrubbing failed: {e}. Falling back to regex.")
            return self.scrub_text_regex(text)
    
    def scrub_text_regex(self, text: str) -> str:
        """
        Scrub PII from text using regex patterns
        
        Args:
            text: Text to scrub
            
        Returns:
            Scrubbed text with PII replaced
        """
        if not text or not isinstance(text, str):
            return text
        
        for entity_type, (pattern, replacement) in self.patterns.items():
            text = re.sub(pattern, replacement, text)
        
        return text
    
    def scrub_value(self, value: Any) -> Any:
        """
        Recursively scrub PII from any data structure
        
        Args:
            value: Value to scrub (can be str, dict, list, or other)
            
        Returns:
            Scrubbed value with same structure
        """
        if isinstance(value, str):
            if self.use_presidio:
                return self.scrub_text_presidio(value)
            else:
                return self.scrub_text_regex(value)
        elif isinstance(value, dict):
            return {k: self.scrub_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.scrub_value(item) for item in value]
        else:
            # Non-string primitives pass through unchanged
            return value
    
    def scrub(self, alert: Any) -> Dict[str, Any]:
        """
        Main scrubbing entry point
        
        Args:
            alert: Alert object or dict to scrub
            
        Returns:
            Dictionary with all PII redacted
        """
        # Convert alert to dict if needed
        if hasattr(alert, 'model_dump'):
            alert_dict = alert.model_dump()
        elif hasattr(alert, 'dict'):
            alert_dict = alert.dict()
        elif isinstance(alert, dict):
            alert_dict = alert
        else:
            raise ValueError(f"Unsupported alert type: {type(alert)}")
        
        # Scrub recursively
        scrubbed = self.scrub_value(alert_dict)
        
        mode = "Presidio" if self.use_presidio else "Regex"
        logger.debug(f"PII scrubbing complete using {mode}")
        
        return scrubbed


# Global scrubber instance for convenience
_default_scrubber = None

def get_default_scrubber() -> PIIScrubber:
    """Get or create the default scrubber instance"""
    global _default_scrubber
    if _default_scrubber is None:
        _default_scrubber = PIIScrubber()
    return _default_scrubber


def scrub_pii(alert) -> Dict[str, Any]:
    """
    Convenience function for PII scrubbing using default configuration
    
    This function maintains backward compatibility while using the
    enhanced PIIScrubber class under the hood.
    
    Args:
        alert: Alert object or dict to scrub
        
    Returns:
        Dictionary with all PII redacted
    """
    scrubber = get_default_scrubber()
    return scrubber.scrub(alert)


def scrub_with_presidio(
    text: str,
    min_confidence: float = 0.5,
    entities: Optional[List[str]] = None
) -> str:
    """
    Direct Presidio scrubbing for single text strings
    
    Args:
        text: Text to scrub
        min_confidence: Minimum confidence threshold
        entities: List of entity types to detect (None = all)
        
    Returns:
        Scrubbed text
        
    Example:
        >>> scrubbed = scrub_with_presidio("Contact john@example.com at 555-1234")
        >>> print(scrubbed)
        "Contact [EMAIL_REDACTED] at [PHONE_REDACTED]"
    """
    if not PRESIDIO_AVAILABLE:
        logger.warning("Presidio not available, falling back to regex")
        scrubber = PIIScrubber(use_presidio=False)
        return scrubber.scrub_text_regex(text)
    
    scrubber = PIIScrubber(min_confidence=min_confidence)
    if entities:
        scrubber.presidio_entities = entities
    
    return scrubber.scrub_text_presidio(text)
