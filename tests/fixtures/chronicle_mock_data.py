"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Mock Chronicle Data for Demos and Testing

Provides realistic Chronicle UDM events, API responses, and webhook payloads
for demonstrating the integration without requiring Chronicle credentials.

Usage:
    from tests.fixtures.chronicle_mock_data import *
    
    # Get realistic UDM alert
    alert = get_mock_idor_alert()
    
    # Get prevalence response
    prevalence = get_mock_prevalence_response("abc123hash")
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List
import random


# ============================================================================
# Mock UDM Events (Chronicle Unified Data Model)
# ============================================================================

def get_mock_udm_event(
    loan_id: int = 4395669,
    user_id: str = "user_12849",
    user_email: str = "attacker@example.com",
    source_ip: str = "192.168.1.100",
    session_id: str = "sess_abc123xyz",
    response_code: int = 403,
    timestamp: datetime = None,
) -> Dict[str, Any]:
    """
    Generate realistic Chronicle UDM event for HTTP request.
    
    This matches Chronicle's actual UDM schema for web logs.
    """
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    return {
        "metadata": {
            "event_type": "HTTP_REQUEST",
            "event_timestamp": timestamp.isoformat() + "Z",
            "product_name": "Acme Web Application Firewall",
            "vendor_name": "Acme Financial",
            "log_type": "APPLICATION_LOG",
        },
        "network": {
            "http": {
                "method": "GET",
                "response_code": response_code,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "referrer": "https://app.acme.com/dashboard",
                "request_headers": {
                    "cookie": f"session_id={session_id}; user_pref=dark_mode",
                    "x-acme-id": session_id,
                    "x-datadog-session-id": session_id,
                    "accept": "application/json",
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiIs...",
                },
                "response_headers": {
                    "content-type": "application/json",
                    "x-request-id": f"req_{random.randint(100000, 999999)}",
                },
            },
            "session_id": session_id,
        },
        "principal": {
            "user": {
                "user_id": user_id,
                "email_addresses": [user_email],
                "user_display_name": user_email.split("@")[0],
            },
            "ip": [source_ip],
            "port": random.randint(50000, 60000),
            "hostname": f"{user_id}-laptop.corp.acme.com",
            "location": {
                "city": "San Francisco",
                "region_code": "CA",
                "country_code": "US",
            },
        },
        "target": {
            "url": f"https://api.acme.com/api/v1/consumer/loan_applications/{loan_id}",
            "hostname": "api.acme.com",
            "port": 443,
            "resource": {
                "name": f"loan_application_{loan_id}",
                "resource_type": "LOAN_APPLICATION",
                "resource_subtype": "CONSUMER_LOAN",
            },
        },
        "security_result": [
            {
                "action": "BLOCK",
                "rule_id": "authorization_check_001",
                "rule_name": "Ownership Validation",
                "category": "AUTHORIZATION_FAILURE",
                "severity": "MEDIUM",
                "description": f"User {user_id} attempted to access loan {loan_id} owned by another user",
            }
        ],
    }


def get_mock_idor_alert(
    num_attempts: int = 4,
    sequential: bool = True,
) -> Dict[str, Any]:
    """
    Generate realistic Chronicle YARA-L alert for IDOR enumeration.
    
    This is what the middleware receives via webhook.
    """
    base_timestamp = datetime.utcnow() - timedelta(minutes=2)
    session_id = f"sess_{random.randint(100000, 999999)}"
    user_id = f"user_{random.randint(10000, 99999)}"
    user_email = "attacker@evil.com"
    source_ip = f"203.0.113.{random.randint(1, 254)}"  # TEST-NET-3 (RFC 5737)
    
    # Generate sequential or random loan IDs
    if sequential:
        base_loan_id = random.randint(4300000, 4400000)
        loan_ids = [base_loan_id + i for i in range(num_attempts)]
    else:
        loan_ids = [random.randint(4300000, 4500000) for _ in range(num_attempts)]
    
    # Generate UDM events
    udm_events = []
    for i, loan_id in enumerate(loan_ids):
        timestamp = base_timestamp + timedelta(seconds=i * 15)  # 15 seconds apart
        udm_events.append(
            get_mock_udm_event(
                loan_id=loan_id,
                user_id=user_id,
                user_email=user_email,
                source_ip=source_ip,
                session_id=session_id,
                response_code=403,
                timestamp=timestamp,
            )
        )
    
    # Chronicle alert wrapper
    return {
        "rule_id": "idor_sequential_enumeration_trigger",
        "rule_name": "IDOR Sequential Enumeration",
        "rule_version": "1.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": "MEDIUM",
        "udm_events": udm_events,
        "distinct_resources": len(loan_ids),
        "session_id": session_id,
        "user_id": user_id,
        "risk_score": 75 if sequential else 60,
        "detection_metadata": {
            "time_window": "5m",
            "pattern_type": "sequential" if sequential else "random",
            "velocity": len(loan_ids) / 5.0,  # Attempts per minute
        },
    }


# ============================================================================
# Mock Chronicle API Responses
# ============================================================================

def get_mock_prevalence_response(
    indicator: str,
    indicator_type: str = "hash",
    affected_count: int = None,
) -> Dict[str, Any]:
    """
    Generate realistic Chronicle prevalence API response.
    
    Simulates asset prevalence query: "How many hosts have seen this IOC?"
    """
    if affected_count is None:
        # Randomize for realism
        affected_count = random.choice([0, 1, 3, 5, 12, 47])  # Realistic distribution
    
    first_seen = datetime.utcnow() - timedelta(days=random.randint(1, 30))
    last_seen = datetime.utcnow() - timedelta(hours=random.randint(1, 12))
    
    # Generate realistic hostnames
    asset_names = []
    for i in range(min(affected_count, 10)):  # Chronicle returns up to 10
        asset_type = random.choice(["web", "api", "db", "worker", "batch"])
        region = random.choice(["us-east", "us-west", "eu-central"])
        asset_names.append(f"{asset_type}-server-{i+1:02d}.{region}.acme.com")
    
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "affected_asset_count": affected_count,
        "affected_asset_names": asset_names,
        "first_seen": first_seen.isoformat() + "Z",
        "last_seen": last_seen.isoformat() + "Z",
        "metadata": {
            "query_time": datetime.utcnow().isoformat() + "Z",
            "time_range": "30d",
            "data_sources": ["proxy_logs", "edr_telemetry", "dns_logs"],
        },
    }


def get_mock_user_baseline_response(
    user_id: str,
    is_normal: bool = True,
) -> Dict[str, Any]:
    """
    Generate realistic Chronicle user baseline response.
    
    Simulates user behavior baseline: "Is this user behavior normal?"
    """
    if is_normal:
        # Normal user baseline
        locations = ["San Francisco, CA", "Oakland, CA", "Berkeley, CA"]
        source_ips = [f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(3)]
        avg_logins = round(random.uniform(1.5, 3.5), 1)
    else:
        # Anomalous baseline (attacker)
        locations = ["Tokyo, JP", "Moscow, RU", "Lagos, NG"]
        source_ips = [f"203.0.113.{random.randint(1, 254)}" for _ in range(5)]
        avg_logins = round(random.uniform(0.2, 1.0), 1)
    
    return {
        "user_id": user_id,
        "typical_locations": locations,
        "typical_source_ips": source_ips,
        "typical_user_agents": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)",
        ],
        "average_daily_logins": avg_logins,
        "baseline_period_days": 30,
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "behavioral_flags": [] if is_normal else ["unusual_location", "new_device"],
    }


def get_mock_network_context_response(
    ip_address: str,
    is_known: bool = False,
) -> Dict[str, Any]:
    """
    Generate realistic Chronicle network context response.
    
    Simulates network context: "Has this IP connected before?"
    """
    if is_known:
        # Known IP with history
        first_seen = datetime.utcnow() - timedelta(days=random.randint(30, 180))
        last_seen = datetime.utcnow() - timedelta(hours=random.randint(1, 24))
        connection_count = random.randint(50, 500)
        connected_assets = [
            f"web-server-{i:02d}.us-west.acme.com"
            for i in range(1, 6)
        ]
        reputation_score = random.randint(70, 95)
    else:
        # New/unknown IP
        first_seen = None
        last_seen = None
        connection_count = 0
        connected_assets = []
        reputation_score = None
    
    return {
        "ip_address": ip_address,
        "first_seen": first_seen.isoformat() + "Z" if first_seen else None,
        "last_seen": last_seen.isoformat() + "Z" if last_seen else None,
        "connection_count": connection_count,
        "connected_assets": connected_assets,
        "reputation_score": reputation_score,
        "threat_intel": {
            "is_malicious": False if is_known else None,
            "categories": ["proxy", "vpn"] if not is_known else [],
            "sources": ["VirusTotal", "AbuseIPDB"] if not is_known else [],
        },
        "geolocation": {
            "city": "Unknown",
            "country": "Unknown",
            "asn": f"AS{random.randint(10000, 99999)}",
            "isp": "Unknown Provider" if not is_known else "Acme Corporate VPN",
        },
    }


# ============================================================================
# Scenario Generators (For Complete Demos)
# ============================================================================

def get_demo_scenario_high_confidence_idor() -> Dict[str, Any]:
    """
    Demo Scenario 1: High-confidence IDOR attack (sequential, fast).
    
    Expected Outcome: CRITICAL alert, auto-case creation.
    """
    alert = get_mock_idor_alert(num_attempts=4, sequential=True)
    
    # Mock Chronicle context showing this is anomalous
    context = {
        "prevalence": {
            "file_hash_none": get_mock_prevalence_response("none", affected_count=0),
        },
        "user_baseline": get_mock_user_baseline_response(
            alert["user_id"],
            is_normal=False  # Anomalous behavior
        ),
        "network_context": get_mock_network_context_response(
            alert["udm_events"][0]["principal"]["ip"][0],
            is_known=False  # Unknown IP
        ),
    }
    
    return {
        "scenario": "high_confidence_idor",
        "description": "Sequential IDOR enumeration from unknown IP with no baseline",
        "alert": alert,
        "chronicle_context": context,
        "expected_verdict": "CRITICAL_IDOR_ATTACK",
        "expected_confidence": 0.95,
        "expected_actions": ["create_chronicle_case", "annotate_udm", "block_session"],
    }


def get_demo_scenario_qa_testing() -> Dict[str, Any]:
    """
    Demo Scenario 2: QA automation testing (false positive).
    
    Expected Outcome: FALSE_POSITIVE, no case creation.
    """
    alert = get_mock_idor_alert(num_attempts=5, sequential=False)
    
    # Mark user as QA tester
    alert["user_id"] = "user_qa_automation_001"
    alert["udm_events"][0]["principal"]["user"]["email_addresses"] = ["qa-bot@acme.com"]
    alert["udm_events"][0]["principal"]["user"]["user_id"] = "user_qa_automation_001"
    
    # Add QA tag to metadata
    for event in alert["udm_events"]:
        event["metadata"]["product_name"] = "Acme QA Test Suite"
        event["principal"]["user"]["user_display_name"] = "QA Automation Bot"
    
    context = {
        "user_baseline": get_mock_user_baseline_response(
            alert["user_id"],
            is_normal=True  # Known QA tester
        ),
        "network_context": get_mock_network_context_response(
            alert["udm_events"][0]["principal"]["ip"][0],
            is_known=True  # Known QA infrastructure
        ),
    }
    
    return {
        "scenario": "qa_testing_false_positive",
        "description": "QA automation testing with known test accounts",
        "alert": alert,
        "chronicle_context": context,
        "expected_verdict": "FALSE_POSITIVE",
        "expected_confidence": 0.95,
        "expected_actions": ["log_only", "no_case"],
        "business_context_applied": True,
    }


def get_demo_scenario_legitimate_customer() -> Dict[str, Any]:
    """
    Demo Scenario 3: Legitimate customer with multiple loans (false positive).
    
    Expected Outcome: FALSE_POSITIVE (accessing own resources).
    """
    alert = get_mock_idor_alert(num_attempts=3, sequential=True)
    
    # Customer accessing their own loans
    alert["user_id"] = "user_12345_legitimate"
    alert["udm_events"][0]["principal"]["user"]["email_addresses"] = ["john.doe@gmail.com"]
    
    # Add ownership context (would be filtered by middleware)
    for event in alert["udm_events"]:
        event["security_result"][0]["description"] = (
            f"User {alert['user_id']} accessing own loan applications (authorized)"
        )
    
    context = {
        "user_baseline": get_mock_user_baseline_response(
            alert["user_id"],
            is_normal=True  # Normal customer
        ),
        "network_context": get_mock_network_context_response(
            "10.0.15.42",  # Internal IP
            is_known=True
        ),
    }
    
    return {
        "scenario": "legitimate_customer_own_resources",
        "description": "Customer accessing their own loan applications",
        "alert": alert,
        "chronicle_context": context,
        "expected_verdict": "FALSE_POSITIVE",
        "expected_confidence": 0.99,
        "expected_actions": ["log_only"],
        "notes": "Ownership filter would prevent this from reaching LLM in production",
    }


def get_demo_scenario_insider_threat() -> Dict[str, Any]:
    """
    Demo Scenario 4: Insider threat (employee snooping).
    
    Expected Outcome: HIGH alert, investigate immediately.
    """
    alert = get_mock_idor_alert(num_attempts=6, sequential=False)
    
    # Internal employee account
    alert["user_id"] = "employee_sarah_jenkins"
    alert["udm_events"][0]["principal"]["user"]["email_addresses"] = ["sarah.jenkins@acme.com"]
    alert["udm_events"][0]["principal"]["hostname"] = "ACME-LAPTOP-1234.corp.acme.com"
    
    # Accessing customer loans they shouldn't have access to
    for event in alert["udm_events"]:
        event["security_result"][0]["description"] = (
            "Employee accessing customer loans outside their assigned portfolio"
        )
    
    context = {
        "user_baseline": get_mock_user_baseline_response(
            alert["user_id"],
            is_normal=True  # Normal employee baseline (not typical attacker)
        ),
        "network_context": get_mock_network_context_response(
            "10.0.50.123",  # Corporate network
            is_known=True
        ),
    }
    
    return {
        "scenario": "insider_threat_employee",
        "description": "Employee accessing customer records outside their role",
        "alert": alert,
        "chronicle_context": context,
        "expected_verdict": "INSIDER_THREAT",
        "expected_confidence": 0.85,
        "expected_actions": ["create_hr_case", "notify_security_team", "audit_access"],
        "mitre_tactics": ["TA0009", "TA0010"],  # Collection, Exfiltration
        "compliance_flags": ["PCI_DSS", "SOC_2_CC6.1"],
    }


# ============================================================================
# Utility Functions
# ============================================================================

def get_all_demo_scenarios() -> List[Dict[str, Any]]:
    """Get all demo scenarios for testing/presentation."""
    return [
        get_demo_scenario_high_confidence_idor(),
        get_demo_scenario_qa_testing(),
        get_demo_scenario_legitimate_customer(),
        get_demo_scenario_insider_threat(),
    ]


def print_scenario_summary():
    """Print summary of all available demo scenarios."""
    scenarios = get_all_demo_scenarios()
    
    print("=== Chronicle Mock Data Demo Scenarios ===\n")
    for i, scenario in enumerate(scenarios, 1):
        print(f"{i}. {scenario['scenario'].upper()}")
        print(f"   Description: {scenario['description']}")
        print(f"   Expected: {scenario['expected_verdict']} (confidence: {scenario['expected_confidence']})")
        print(f"   Actions: {', '.join(scenario['expected_actions'])}")
        print()


if __name__ == "__main__":
    print_scenario_summary()
