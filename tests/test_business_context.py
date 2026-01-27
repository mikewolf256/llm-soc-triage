"""
Tests for Business Context Manager - The "RAG Logic"

These tests prove the system enriches alerts with institutional knowledge.

Interview Point: "Without business context, every PowerShell execution looks
equally suspicious. With it, we know svc_accounting running scripts is expected,
but marketing_intern_01 doing the same is a red flag."
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.context_manager import BusinessContextManager, format_business_context_for_prompt


class TestBusinessContextManager:
    """Test business context enrichment logic"""
    
    @pytest.fixture
    def context_mgr(self):
        """Create a BusinessContextManager instance for testing"""
        return BusinessContextManager()
    
    def test_critical_asset_detection(self, context_mgr):
        """Should identify critical assets from business context"""
        # Production DB server is marked as critical
        result = context_mgr.is_critical_asset("prod-db-01.internal")
        
        assert result["is_critical"] == True
        assert result["role"] == "Primary Database Server"
        assert result["risk_level"] == "critical"
        assert "dba_team" in result["allowed_users"]
    
    def test_non_critical_asset(self, context_mgr):
        """Non-critical assets should return False"""
        result = context_mgr.is_critical_asset("some-workstation.internal")
        
        assert result["is_critical"] == False
    
    def test_case_insensitive_asset_matching(self, context_mgr):
        """Asset matching should be case-insensitive"""
        result = context_mgr.is_critical_asset("PROD-DB-01.INTERNAL")
        
        assert result["is_critical"] == True
    
    def test_vip_user_detection(self, context_mgr):
        """Should identify VIP users with elevated privileges"""
        result = context_mgr.is_vip_user("dba_team")
        
        assert result["is_vip"] == True
        assert "database_admin" in result["privileges"]
        assert "justification" in result
    
    def test_non_vip_user(self, context_mgr):
        """Regular users should return False"""
        result = context_mgr.is_vip_user("marketing_intern_01")
        
        assert result["is_vip"] == False
    
    def test_redacted_user_handling(self, context_mgr):
        """Should handle PII-redacted usernames gracefully"""
        result = context_mgr.is_vip_user("[EMAIL_REDACTED]")
        
        assert result["is_vip"] == False
        assert "redacted" in result.get("note", "").lower()
    
    def test_approved_admin_tool_detection(self, context_mgr):
        """Should identify approved admin tools"""
        result = context_mgr.is_approved_tool("powershell.exe")
        
        assert result["is_approved"] == True
        assert "allowed_contexts" in result
        assert "risk_notes" in result
    
    def test_unapproved_tool(self, context_mgr):
        """Unapproved tools should return False"""
        result = context_mgr.is_approved_tool("malware.exe")
        
        assert result["is_approved"] == False
    
    def test_known_false_positive_pattern(self, context_mgr):
        """Should detect known false positive patterns"""
        alert_desc = "Multiple failed SSH attempts from 10.50.100.5 detected"
        
        result = context_mgr.check_known_false_positive(alert_desc)
        
        assert result is not None
        assert result["is_false_positive"] == True
        assert "vulnerability scanner" in result["reason"].lower()
        assert result["recommended_action"] == "close"
    
    def test_no_false_positive_match(self, context_mgr):
        """Novel alerts should not match false positive patterns"""
        alert_desc = "Suspicious malware execution detected"
        
        result = context_mgr.check_known_false_positive(alert_desc)
        
        assert result is None
    
    def test_risk_multiplier_calculation(self, context_mgr):
        """Should calculate risk multiplier for high-risk patterns"""
        alert_desc = "Outbound connection to known C2 infrastructure detected"
        iocs = ["185.220.101.42"]
        
        multiplier = context_mgr.calculate_risk_multiplier(alert_desc, iocs)
        
        assert multiplier > 1.0
    
    def test_risk_multiplier_no_match(self, context_mgr):
        """Benign alerts should have multiplier of 1.0"""
        alert_desc = "Regular system update process"
        iocs = []
        
        multiplier = context_mgr.calculate_risk_multiplier(alert_desc, iocs)
        
        assert multiplier == 1.0
    
    def test_full_alert_enrichment(self, context_mgr):
        """
        Test full enrichment pipeline with realistic alert
        
        Interview Point: "This is the 'secret sauce' - we inject all
        institutional knowledge before the LLM sees the alert."
        """
        alert = {
            "alert_id": "CRS-2026-0042",
            "description": "User executed powershell.exe with base64 encoding",
            "affected_user": "dba_team",
            "affected_host": "prod-db-01.internal",
            "iocs": []
        }
        
        enrichment = context_mgr.enrich_alert(alert)
        
        # Should have business context
        assert "business_context" in enrichment
        
        # Should identify critical asset
        assert "critical_asset" in enrichment["business_context"]
        assert enrichment["business_context"]["critical_asset"]["is_critical"] == True
        
        # Should identify VIP user
        assert "vip_user" in enrichment["business_context"]
        assert enrichment["business_context"]["vip_user"]["is_vip"] == True
        
        # Should identify approved tool
        assert "approved_tool" in enrichment["business_context"]
        assert enrichment["business_context"]["approved_tool"]["is_approved"] == True
    
    def test_suspicious_alert_enrichment(self, context_mgr):
        """
        Test enrichment with suspicious activity (high risk)
        
        Marketing intern running PowerShell on workstation = suspicious
        DBA running PowerShell on DB server = expected
        """
        alert = {
            "alert_id": "TEST-SUSPICIOUS",
            "description": "Outbound connection to known C2 infrastructure and credential dumping detected",
            "affected_user": "marketing_intern_01",
            "affected_host": "workstation-123",
            "iocs": ["185.220.101.42", "mimikatz.exe"]
        }
        
        enrichment = context_mgr.enrich_alert(alert)
        
        # Should have risk multiplier due to C2 and credential dumping
        assert enrichment["business_context"].get("risk_multiplier", 1.0) > 1.0
        
        # Should NOT have VIP user context (marketing intern)
        assert "vip_user" not in enrichment["business_context"] or \
               not enrichment["business_context"]["vip_user"].get("is_vip", False)
        
        # Should NOT have critical asset context (workstation)
        assert "critical_asset" not in enrichment["business_context"] or \
               not enrichment["business_context"]["critical_asset"].get("is_critical", False)
    
    def test_false_positive_enrichment(self, context_mgr):
        """Test enrichment with known false positive"""
        alert = {
            "alert_id": "TEST-FP",
            "description": "PowerShell base64 encoding by svc_backup detected",
            "affected_user": "svc_backup",
            "affected_host": "backup-server-01",
            "iocs": []
        }
        
        enrichment = context_mgr.enrich_alert(alert)
        
        # Should detect known false positive
        assert "known_false_positive" in enrichment["business_context"]
        assert enrichment["business_context"]["known_false_positive"]["is_false_positive"] == True


class TestBusinessContextFormatting:
    """Test business context formatting for prompts"""
    
    def test_format_with_critical_asset(self):
        """Should format critical asset context for LLM"""
        enrichment = {
            "business_context": {
                "critical_asset": {
                    "is_critical": True,
                    "role": "Primary Database Server",
                    "risk_level": "critical",
                    "allowed_users": ["dba_team", "svc_backup"]
                }
            }
        }
        
        formatted = format_business_context_for_prompt(enrichment)
        
        assert "Critical Asset Involved" in formatted
        assert "Primary Database Server" in formatted
        assert "dba_team" in formatted
    
    def test_format_with_vip_user(self):
        """Should format VIP user context for LLM"""
        enrichment = {
            "business_context": {
                "vip_user": {
                    "is_vip": True,
                    "privileges": ["database_admin", "backup_restore"],
                    "justification": "Database administration team"
                }
            }
        }
        
        formatted = format_business_context_for_prompt(enrichment)
        
        assert "Privileged User" in formatted
        assert "database_admin" in formatted
        assert "Database administration team" in formatted
    
    def test_format_with_known_false_positive(self):
        """Should format known false positive for LLM"""
        enrichment = {
            "business_context": {
                "known_false_positive": {
                    "is_false_positive": True,
                    "reason": "Internal vulnerability scanner",
                    "recommended_action": "close",
                    "last_reviewed": "2026-01-15"
                }
            }
        }
        
        formatted = format_business_context_for_prompt(enrichment)
        
        assert "Known False Positive" in formatted
        assert "vulnerability scanner" in formatted
        assert "close" in formatted
    
    def test_format_with_risk_multiplier(self):
        """Should format risk multiplier for LLM"""
        enrichment = {
            "business_context": {
                "risk_multiplier": 3.0
            }
        }
        
        formatted = format_business_context_for_prompt(enrichment)
        
        assert "Risk Multiplier" in formatted
        assert "3.0x" in formatted
    
    def test_format_empty_context(self):
        """Should handle empty context gracefully"""
        enrichment = {"business_context": {}}
        
        formatted = format_business_context_for_prompt(enrichment)
        
        assert "No additional business context available" in formatted
    
    def test_format_multiple_contexts(self):
        """Should format multiple context elements together"""
        enrichment = {
            "business_context": {
                "critical_asset": {
                    "is_critical": True,
                    "role": "Financial System",
                    "risk_level": "critical",
                    "allowed_users": ["finance_team"]
                },
                "vip_user": {
                    "is_vip": True,
                    "privileges": ["financial_reports"],
                    "justification": "Finance team"
                },
                "risk_multiplier": 2.5
            }
        }
        
        formatted = format_business_context_for_prompt(enrichment)
        
        assert "Critical Asset" in formatted
        assert "Privileged User" in formatted
        assert "Risk Multiplier" in formatted
        assert "Financial System" in formatted
        assert "finance_team" in formatted


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
