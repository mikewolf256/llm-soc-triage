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
