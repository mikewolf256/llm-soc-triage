"""
Business Context Manager - The RAG Logic

In fintech environments, raw alerts without business context are useless.
"Suspicious PowerShell" means different things depending on:
- WHO ran it (DBA vs marketing intern)
- WHERE it ran (production DB server vs test workstation)
- WHAT they executed (approved admin tool vs unknown binary)

This module enriches alerts with institutional knowledge before LLM triage.

Chronicle Integration:
    When enabled, adds Chronicle-backed enrichment (prevalence, baselines, network intel).
    All Chronicle API responses are PII-scrubbed before LLM context injection.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class BusinessContextManager:
    """
    Manages business context for alert triage enrichment
    
    This is the "secret sauce" that makes AI triage valuable in production.
    Without this, every PowerShell execution looks equally suspicious.
    With this, we know that svc_accounting running scripts is expected.
    
    Chronicle Integration:
        When enabled, adds Chronicle-backed enrichment in parallel with
        local business rules. All Chronicle data is PII-scrubbed.
    """
    
    def __init__(
        self,
        context_file: Optional[str] = None,
        enable_chronicle: bool = None,
    ):
        """
        Initialize with business context data
        
        Args:
            context_file: Path to business_context.json. Defaults to data/business_context.json
            enable_chronicle: Enable Chronicle enrichment (default: from env CHRONICLE_CONTEXT_ENRICHMENT)
        """
        if context_file is None:
            # Default to data/business_context.json relative to project root
            context_file = Path(__file__).parent.parent / "data" / "business_context.json"
        
        self.context_file = Path(context_file)
        self.context = self._load_context()
        
        # Chronicle integration (lazy loaded)
        self.chronicle_enabled = enable_chronicle if enable_chronicle is not None \
                                else os.getenv("CHRONICLE_CONTEXT_ENRICHMENT", "false").lower() == "true"
        self.chronicle_enricher = None
        
        if self.chronicle_enabled:
            try:
                from .chronicle_integration import ChronicleClient, ChronicleContextEnricher
                chronicle_client = ChronicleClient()
                if chronicle_client.is_configured():
                    self.chronicle_enricher = ChronicleContextEnricher(chronicle_client)
                    logger.info("Chronicle context enrichment enabled")
                else:
                    logger.warning("Chronicle enabled but not configured")
                    self.chronicle_enabled = False
            except Exception as e:
                logger.warning(f"Chronicle enrichment initialization failed: {e}")
                self.chronicle_enabled = False
    
    def _load_context(self) -> Dict[str, Any]:
        """Load business context from JSON file"""
        try:
            with open(self.context_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Graceful degradation if context file is missing
            return {
                "critical_assets": {"servers": [], "services": []},
                "vip_users": [],
                "approved_admin_tools": [],
                "known_false_positives": [],
                "high_risk_patterns": []
            }
    
    def is_critical_asset(self, hostname: Optional[str]) -> Dict[str, Any]:
        """
        Check if a hostname is a critical asset
        
        Returns enrichment data about the asset's role and risk level.
        """
        if not hostname:
            return {"is_critical": False}
        
        for server in self.context.get("critical_assets", {}).get("servers", []):
            if server["hostname"].lower() == hostname.lower():
                return {
                    "is_critical": True,
                    "role": server["role"],
                    "risk_level": server["risk_level"],
                    "allowed_users": server["allowed_users"]
                }
        
        return {"is_critical": False}
    
    def is_vip_user(self, username: Optional[str]) -> Dict[str, Any]:
        """
        Check if a user has elevated privileges
        
        Returns justification for why this user should have access.
        """
        if not username:
            return {"is_vip": False}
        
        # Handle redacted usernames
        if "[EMAIL_REDACTED]" in str(username) or "[REDACTED]" in str(username):
            return {"is_vip": False, "note": "Username was redacted for PII compliance"}
        
        for vip in self.context.get("vip_users", []):
            if vip["user_role"].lower() in username.lower():
                return {
                    "is_vip": True,
                    "privileges": vip["privileges"],
                    "justification": vip["justification"]
                }
        
        return {"is_vip": False}
    
    def is_approved_tool(self, process_name: Optional[str]) -> Dict[str, Any]:
        """
        Check if a process is an approved admin tool
        
        Returns allowed contexts and risk notes.
        """
        if not process_name:
            return {"is_approved": False}
        
        process_name_lower = process_name.lower()
        
        for tool in self.context.get("approved_admin_tools", []):
            if tool["process"].lower() in process_name_lower:
                return {
                    "is_approved": True,
                    "allowed_contexts": tool["allowed_contexts"],
                    "risk_notes": tool["risk_notes"]
                }
        
        return {"is_approved": False}
    
    def check_known_false_positive(self, alert_description: str) -> Optional[Dict[str, Any]]:
        """
        Check if alert matches known false positive patterns
        
        This is how we reduce alert fatigue - institutional knowledge
        about recurring noise that's been previously investigated.
        """
        for fp in self.context.get("known_false_positives", []):
            # Simple substring match - in production you'd use regex or embeddings
            if fp["pattern"].lower() in alert_description.lower():
                return {
                    "is_false_positive": True,
                    "reason": fp["reason"],
                    "recommended_action": fp["recommended_action"],
                    "last_reviewed": fp["last_reviewed"]
                }
        
        return None
    
    def calculate_risk_multiplier(self, alert_description: str, iocs: List[str]) -> float:
        """
        Calculate risk multiplier based on high-risk patterns
        
        This adjusts the base severity based on business context.
        Lateral movement to production servers is worse than workstation activity.
        """
        multiplier = 1.0
        matched_patterns = []
        
        alert_text = alert_description.lower()
        ioc_text = " ".join(iocs).lower()
        combined_text = f"{alert_text} {ioc_text}"
        
        for pattern in self.context.get("high_risk_patterns", []):
            indicator = pattern["indicator"].lower()
            if indicator in combined_text:
                multiplier = max(multiplier, pattern["severity_multiplier"])
                matched_patterns.append(pattern["indicator"])
        
        return multiplier
    
    def detect_idor_pattern(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect IDOR enumeration patterns in Chronicle UDM alerts
        
        Returns: IDOR context if pattern detected, None otherwise
        """
        raw_data = alert.get("raw_data", {})
        
        # Extract IDOR signals
        distinct_resources = raw_data.get("distinct_resources", 0)
        description = alert.get("description", "")
        
        is_sequential = "sequential" in description.lower()
        sequential_threshold = self.context.get("idor_detection_rules", {}).get("sequential_threshold", 3)
        is_high_velocity = distinct_resources >= sequential_threshold
        
        if is_sequential and is_high_velocity:
            return {
                "idor_detected": True,
                "pattern_type": "sequential_enumeration",
                "resource_count": distinct_resources,
                "severity": "high" if distinct_resources >= 4 else "medium",
                "recommended_verdict": "CRITICAL_IDOR_ATTACK"
            }
        
        return None
    
    def is_qa_test_activity(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if activity matches QA testing patterns.
        Note: Checks data that survives PII scrubbing (product names, display names, user IDs).
        
        Returns: QA context if detected, None otherwise
        """
        qa_config = self.context.get("qa_infrastructure", {})
        
        affected_user = alert.get("affected_user", "")
        description = alert.get("description", "")
        raw_data = alert.get("raw_data", {})
        
        # Build comprehensive search text including UDM event data
        search_text = f"{affected_user} {description}".lower()
        
        # Check UDM events for QA indicators (focus on non-PII fields)
        udm_events = raw_data.get("udm_sample_events", [])
        for event in udm_events:
            # Check product name (NOT scrubbed)
            product_name = event.get("metadata", {}).get("product_name", "")
            search_text += f" {product_name}".lower()
            
            # Check user display name (NOT scrubbed)
            user_info = event.get("principal", {}).get("user", {})
            display_name = user_info.get("user_display_name", "")
            search_text += f" {display_name}".lower()
            
            # Check user_id (NOT scrubbed)
            user_id = user_info.get("user_id", "")
            search_text += f" {user_id}".lower()
        
        # Check for QA product names (highest confidence - these survive scrubbing)
        for product_name in qa_config.get("test_product_names", []):
            if product_name.lower() in search_text:
                return {
                    "is_qa_testing": True,
                    "reason": f"QA testing infrastructure detected: {product_name}",
                    "recommended_verdict": "FALSE_POSITIVE",
                    "recommended_actions": ["close_as_expected_qa_activity"]
                }
        
        # Check for QA display names
        for display_name in qa_config.get("test_display_names", []):
            if display_name.lower() in search_text:
                return {
                    "is_qa_testing": True,
                    "reason": f"QA account detected: {display_name}",
                    "recommended_verdict": "FALSE_POSITIVE",
                    "recommended_actions": ["close_as_expected_qa_activity"]
                }
        
        # Check for QA user IDs
        for user_id_pattern in qa_config.get("test_user_ids", []):
            if user_id_pattern.lower() in search_text:
                return {
                    "is_qa_testing": True,
                    "reason": f"QA user ID detected: contains '{user_id_pattern}'",
                    "recommended_verdict": "FALSE_POSITIVE",
                    "recommended_actions": ["close_as_expected_qa_activity"]
                }
        
        return None
    
    def detect_insider_threat(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect insider threat patterns (employee accessing unauthorized data).
        Note: Focuses on hostnames and user IDs that survive PII scrubbing.
        
        Returns: Insider threat context if detected, None otherwise
        """
        insider_config = self.context.get("insider_threat_indicators", {})
        
        affected_user = alert.get("affected_user", "")
        description = alert.get("description", "").lower()
        raw_data = alert.get("raw_data", {})
        
        # Build comprehensive search text including UDM event data
        search_text = f"{affected_user} {description}".lower()
        
        # Check UDM events for employee indicators (focus on non-PII fields)
        udm_events = raw_data.get("udm_sample_events", [])
        for event in udm_events:
            # Check hostname for corporate identifiers (NOT scrubbed)
            hostname = event.get("principal", {}).get("hostname", "")
            search_text += f" {hostname}".lower()
            
            # Check user_id (NOT scrubbed)
            user_info = event.get("principal", {}).get("user", {})
            user_id = user_info.get("user_id", "")
            search_text += f" {user_id}".lower()
            
            # Check security result descriptions (NOT scrubbed)
            for sec_result in event.get("security_result", []):
                sec_desc = sec_result.get("description", "")
                search_text += f" {sec_desc}".lower()
        
        # Check if employee (by hostname or user_id patterns)
        is_employee = any(
            hostname_pattern in search_text 
            for hostname_pattern in insider_config.get("employee_hostnames", [])
        )
        
        if not is_employee:
            # Also check user_id patterns
            is_employee = any(
                user_id_pattern in search_text
                for user_id_pattern in insider_config.get("employee_user_ids", [])
            )
        
        # Check for suspicious access patterns in descriptions
        is_suspicious = any(
            pattern in search_text 
            for pattern in insider_config.get("suspicious_patterns", [])
        )
        
        if is_employee and is_suspicious:
            return {
                "insider_threat_detected": True,
                "reason": "Employee accessing unauthorized customer resources",
                "recommended_verdict": "INSIDER_THREAT",
                "recommended_actions": [
                    "create_hr_case",
                    "notify_security_team",
                    "audit_access",
                    "pull_full_audit_log"
                ]
            }
        
        return None
    
    async def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich alert with full business context (including Chronicle).
        
        This is the main entry point - takes a raw alert and adds
        all relevant business intelligence before LLM processing.
        
        Flow:
            1. Local business rules (synchronous)
            2. Chronicle context enrichment (async, if enabled)
            3. Combine contexts with PII scrubbing maintained
        
        Security:
            All Chronicle API responses are PII-scrubbed before inclusion.
        """
        enrichment = {
            "business_context": {}
        }
        
        # Check if affected host is critical
        affected_host = alert.get("affected_host")
        if affected_host:
            asset_info = self.is_critical_asset(affected_host)
            if asset_info["is_critical"]:
                enrichment["business_context"]["critical_asset"] = asset_info
        
        # Check if affected user has elevated privileges
        affected_user = alert.get("affected_user")
        if affected_user:
            user_info = self.is_vip_user(affected_user)
            if user_info["is_vip"]:
                enrichment["business_context"]["vip_user"] = user_info
        
        # Check if processes are approved tools
        description = alert.get("description", "")
        if "powershell" in description.lower() or "psexec" in description.lower():
            # Extract process names (simplified - production would use regex)
            for word in description.split():
                tool_info = self.is_approved_tool(word)
                if tool_info["is_approved"]:
                    enrichment["business_context"]["approved_tool"] = tool_info
                    break
        
        # Check for known false positives
        fp_match = self.check_known_false_positive(description)
        if fp_match:
            enrichment["business_context"]["known_false_positive"] = fp_match
        
        # Calculate risk multiplier
        iocs = alert.get("iocs", [])
        risk_multiplier = self.calculate_risk_multiplier(description, iocs)
        if risk_multiplier > 1.0:
            enrichment["business_context"]["risk_multiplier"] = risk_multiplier
        
        # IDOR Detection
        idor_context = self.detect_idor_pattern(alert)
        if idor_context:
            enrichment["business_context"]["idor_detection"] = idor_context
            logger.info(f"IDOR pattern detected: {idor_context['pattern_type']}")
        
        # QA Testing Detection (check this early - if QA, likely false positive)
        qa_context = self.is_qa_test_activity(alert)
        if qa_context:
            enrichment["business_context"]["qa_testing"] = qa_context
            logger.info(f"QA testing activity detected: {qa_context['reason']}")
        
        # Insider Threat Detection
        insider_context = self.detect_insider_threat(alert)
        if insider_context:
            enrichment["business_context"]["insider_threat"] = insider_context
            logger.info(f"Insider threat detected: {insider_context['reason']}")
        
        # Add compliance requirements
        enrichment["business_context"]["compliance"] = self.context.get("compliance_requirements", {})
        
        # Chronicle enrichment (async, PII-scrubbed)
        if self.chronicle_enabled and self.chronicle_enricher:
            try:
                logger.debug(f"Querying Chronicle for additional context: alert_id={alert.get('alert_id')}")
                chronicle_context = await self.chronicle_enricher.enrich_from_chronicle(
                    alert_iocs=iocs,
                    affected_host=affected_host,
                    affected_user=affected_user,
                )
                
                if chronicle_context:
                    enrichment["chronicle_context"] = chronicle_context
                    logger.info(f"Chronicle enrichment added: {len(chronicle_context)} categories")
            except Exception as e:
                logger.error(f"Chronicle enrichment failed: {e}", exc_info=True)
                # Graceful degradation - continue without Chronicle context
        
        return enrichment


def format_business_context_for_prompt(enrichment: Dict[str, Any]) -> str:
    """
    Format business context as human-readable text for LLM prompt
    
    This converts the enrichment dict into natural language that
    the LLM can reason over during triage.
    
    Includes both local business rules and Chronicle context (if available).
    All data is pre-scrubbed for PII safety.
    """
    lines = []
    
    # Local business context
    if enrichment.get("business_context"):
        context = enrichment["business_context"]
        lines.append("### Business Context")
        
        if "critical_asset" in context:
            asset = context["critical_asset"]
            lines.append(f"- **Critical Asset Involved**: {asset['role']} (Risk Level: {asset['risk_level']})")
            lines.append(f"  - Allowed users: {', '.join(asset['allowed_users'])}")
        
        if "vip_user" in context:
            user = context["vip_user"]
            lines.append(f"- **Privileged User**: {user['justification']}")
            lines.append(f"  - Approved privileges: {', '.join(user['privileges'])}")
        
        if "approved_tool" in context:
            tool = context["approved_tool"]
            lines.append(f"- **Approved Admin Tool**: {tool['risk_notes']}")
            lines.append(f"  - Allowed contexts: {', '.join(tool['allowed_contexts'])}")
        
        if "known_false_positive" in context:
            fp = context["known_false_positive"]
            lines.append(f"- **Known False Positive Pattern**: {fp['reason']}")
            lines.append(f"  - Recommended action: {fp['recommended_action']}")
            lines.append(f"  - Last reviewed: {fp['last_reviewed']}")
        
        if "risk_multiplier" in context and context["risk_multiplier"] > 1.0:
            lines.append(f"- **Risk Multiplier**: {context['risk_multiplier']}x (high-risk indicators present)")
        
        if "idor_detection" in context:
            idor = context["idor_detection"]
            lines.append("")
            lines.append(f"**⚠️ IDOR ATTACK PATTERN DETECTED ⚠️**")
            lines.append(f"- Pattern: {idor['pattern_type']} ({idor['resource_count']} resources)")
            lines.append(f"- Severity: {idor['severity'].upper()}")
            lines.append(f"- **STRONG RECOMMENDATION: Classify as {idor['recommended_verdict']}**")
            lines.append(f"- This matches known IDOR exploitation techniques")
        
        if "qa_testing" in context:
            qa = context["qa_testing"]
            lines.append("")
            lines.append(f"**✓ QA Testing Activity Detected**")
            lines.append(f"- {qa['reason']}")
            lines.append(f"- **STRONG RECOMMENDATION: Classify as {qa['recommended_verdict']}**")
            lines.append(f"- This is legitimate automated testing, not a real attack")
        
        if "insider_threat" in context:
            insider = context["insider_threat"]
            lines.append("")
            lines.append(f"**⚠️ INSIDER THREAT INDICATORS ⚠️**")
            lines.append(f"- {insider['reason']}")
            lines.append(f"- **STRONG RECOMMENDATION: Classify as {insider['recommended_verdict']}**")
            lines.append(f"- Immediate actions: {', '.join(insider['recommended_actions'][:2])}")
    
    # Chronicle context (if available)
    if enrichment.get("chronicle_context"):
        chronicle = enrichment["chronicle_context"]
        lines.append("")  # Blank line separator
        lines.append("### Chronicle Security Context")
        
        if "chronicle_prevalence" in chronicle and chronicle["chronicle_prevalence"]:
            lines.append("\n**IOC Prevalence (Past 30 Days):**")
            for ioc, context_text in chronicle["chronicle_prevalence"].items():
                lines.append(f"- `{ioc}`: {context_text}")
        
        if "chronicle_user_baseline" in chronicle:
            lines.append(f"\n**User Baseline:**")
            lines.append(chronicle["chronicle_user_baseline"])
        
        if "chronicle_network_context" in chronicle and chronicle["chronicle_network_context"]:
            lines.append("\n**Network Intelligence:**")
            for ip, context_text in chronicle["chronicle_network_context"].items():
                lines.append(f"- `{ip}`: {context_text}")
    
    return "\n".join(lines) if lines else "No additional business context available."
