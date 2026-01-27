"""
PII Redaction - Keep sensitive data local, only send scrubbed alerts to LLM.
Uses Microsoft Presidio for entity detection.
"""

from typing import Dict, Any
import re
import logging

# TODO: Import Presidio when needed
# from presidio_analyzer import AnalyzerEngine
# from presidio_anonymizer import AnonymizerEngine

logger = logging.getLogger(__name__)


def scrub_pii(alert) -> Dict[str, Any]:
    """
    Redact PII from alert data before sending to LLM
    
    Currently using regex patterns. TODO: Integrate Presidio for better detection.
    
    Redacts:
    - Email addresses → [EMAIL_REDACTED]
    - IP addresses → [IP_REDACTED]  
    - Social Security Numbers → [SSN_REDACTED]
    - Credit card numbers → [CC_REDACTED]
    - Phone numbers → [PHONE_REDACTED]
    """
    
    # Convert alert to dict
    alert_dict = alert.model_dump() if hasattr(alert, 'model_dump') else alert
    
    # Patterns to redact
    patterns = {
        "email": (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
        "ipv4": (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_REDACTED]'),
        "ssn": (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]'),
        "credit_card": (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CC_REDACTED]'),
        "phone": (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REDACTED]'),
    }
    
    def scrub_value(value):
        """Recursively scrub strings"""
        if isinstance(value, str):
            for entity_type, (pattern, replacement) in patterns.items():
                value = re.sub(pattern, replacement, value)
            return value
        elif isinstance(value, dict):
            return {k: scrub_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [scrub_value(item) for item in value]
        return value
    
    scrubbed = scrub_value(alert_dict)
    logger.debug("PII scrubbing complete")
    
    return scrubbed


def scrub_with_presidio(text: str) -> str:
    """
    Enhanced PII detection using Microsoft Presidio
    TODO: Implement when Presidio is needed
    """
    # analyzer = AnalyzerEngine()
    # anonymizer = AnonymizerEngine()
    # 
    # results = analyzer.analyze(text=text, language='en')
    # anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    # 
    # return anonymized.text
    
    logger.warning("Presidio integration not yet implemented, using regex")
    return text
