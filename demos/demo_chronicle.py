#!/usr/bin/env python3
"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Chronicle Integration Demo Script

Interactive demo showing Chronicle integration with realistic mock data.
Perfect for presentations, hiring manager demos, and development.

Usage:
    # Interactive demo
    python demo_chronicle.py
    
    # Run specific scenario
    python demo_chronicle.py --scenario high_confidence_idor
    
    # Run all scenarios
    python demo_chronicle.py --all
"""

import asyncio
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from tests.fixtures.chronicle_mock_data import (
    get_all_demo_scenarios,
    print_scenario_summary,
)


# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def print_header(text: str):
    """Print styled header."""
    print()
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.END}")
    print()


def print_section(text: str):
    """Print section header."""
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
    print(f"{Colors.CYAN}{'-' * len(text)}{Colors.END}")


def print_success(text: str):
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_error(text: str):
    """Print error message."""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_info(text: str):
    """Print info message."""
    print(f"{Colors.CYAN}ℹ {text}{Colors.END}")


def print_json(data: Dict[str, Any], truncate: bool = True):
    """Print formatted JSON."""
    json_str = json.dumps(data, indent=2, default=str)
    
    if truncate and len(json_str) > 2000:
        lines = json_str.split('\n')
        print('\n'.join(lines[:30]))
        print(f"\n{Colors.YELLOW}... (truncated, {len(lines) - 30} more lines){Colors.END}\n")
    else:
        print(json_str)


def simulate_pii_scrubbing(data: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate PII scrubbing on data."""
    json_str = json.dumps(data)
    
    # Simulate scrubbing
    json_str = json_str.replace("192.168.1.100", "[IP_REDACTED]")
    json_str = json_str.replace("203.0.113.", "[IP_REDACTED_")
    json_str = json_str.replace("attacker@evil.com", "[EMAIL_REDACTED]")
    json_str = json_str.replace("attacker@example.com", "[EMAIL_REDACTED]")
    json_str = json_str.replace(".elk.com", "[HOSTNAME_REDACTED]")
    
    return json.loads(json_str)


def run_scenario_demo(scenario: Dict[str, Any]):
    """Run interactive demo for a scenario."""
    print_header(f"Chronicle Integration Demo: {scenario['scenario']}")
    
    print_info(f"Scenario: {scenario['description']}")
    print()
    
    # Step 1: Chronicle Alert (Inbound)
    print_section("Step 1: Chronicle YARA-L Alert (Inbound Gate - RED)")
    print_info("Chronicle detects pattern and sends UDM event to middleware webhook")
    print()
    print(f"{Colors.YELLOW}Raw UDM Alert (Contains PII):{Colors.END}")
    print_json(scenario["alert"], truncate=True)
    
    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    # Step 2: PII Scrubbing
    print_section("Step 2: PII Scrubbing (Mandatory)")
    print_info("Middleware scrubs PII before LLM analysis (GDPR/SOC 2 compliance)")
    print()
    
    scrubbed_alert = simulate_pii_scrubbing(scenario["alert"])
    print(f"{Colors.GREEN}Scrubbed Alert (LLM-Safe):{Colors.END}")
    print_json(scrubbed_alert, truncate=True)
    
    print()
    print_success("IPs → [IP_REDACTED]")
    print_success("Emails → [EMAIL_REDACTED]")
    print_success("Hostnames → [HOSTNAME_REDACTED]")
    print_success("Correlation tokens preserved (user_id, session_id)")
    
    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    # Step 3: Chronicle Context Enrichment
    print_section("Step 3: Chronicle Context Enrichment (Execution Gate - YELLOW)")
    print_info("Middleware queries Chronicle for prevalence, baselines, network intel")
    print()
    
    if "chronicle_context" in scenario:
        context = scenario["chronicle_context"]
        
        if "prevalence" in context:
            print(f"{Colors.CYAN}IOC Prevalence:{Colors.END}")
            for ioc, data in context["prevalence"].items():
                affected = data.get("affected_asset_count", 0)
                if affected == 0:
                    print(f"  • {ioc}: Never seen before (new IOC)")
                elif affected < 5:
                    print(f"  • {ioc}: Seen on {affected} hosts (uncommon)")
                else:
                    print(f"  • {ioc}: Seen on {affected}+ hosts (widespread)")
        
        if "user_baseline" in context:
            print(f"\n{Colors.CYAN}User Baseline:{Colors.END}")
            baseline = context["user_baseline"]
            locations = ", ".join(baseline.get("typical_locations", [])[:2])
            avg_logins = baseline.get("average_daily_logins", 0)
            print(f"  • Typical locations: {locations}")
            print(f"  • Average logins/day: {avg_logins}")
            
            if "behavioral_flags" in baseline and baseline["behavioral_flags"]:
                print(f"  • {Colors.YELLOW}Anomalies: {', '.join(baseline['behavioral_flags'])}{Colors.END}")
        
        if "network_context" in context:
            print(f"\n{Colors.CYAN}Network Intelligence:{Colors.END}")
            net = context["network_context"]
            conn_count = net.get("connection_count", 0)
            if conn_count == 0:
                print(f"  • New IP - 0 prior connections (suspicious)")
            elif conn_count < 50:
                print(f"  • Rare IP - {conn_count} connections")
            else:
                print(f"  • Known IP - {conn_count}+ connections")
    
    print()
    print_success("All Chronicle API responses PII-scrubbed before LLM")
    
    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    # Step 4: LLM Analysis
    print_section("Step 4: LLM Analysis (Claude API)")
    print_info("LLM analyzes scrubbed alert + Chronicle context")
    print()
    
    print(f"{Colors.CYAN}Expected Verdict:{Colors.END} {scenario['expected_verdict']}")
    print(f"{Colors.CYAN}Expected Confidence:{Colors.END} {scenario['expected_confidence'] * 100:.0f}%")
    print(f"{Colors.CYAN}Expected Actions:{Colors.END} {', '.join(scenario['expected_actions'])}")
    
    if "mitre_tactics" in scenario:
        print(f"{Colors.CYAN}MITRE ATT&CK:{Colors.END} {', '.join(scenario['mitre_tactics'])}")
    
    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.END}")
    
    # Step 5: SOAR Integration (Outbound)
    print_section("Step 5: Chronicle SOAR Integration (Outbound Gate - GREEN)")
    print_info("High-confidence alerts trigger Chronicle case creation and UDM annotation")
    print()
    
    if "create_chronicle_case" in scenario["expected_actions"]:
        print_success("Chronicle Case Created: CHR-2026-001234")
        print(f"  • Title: IDOR Attack Detected: {scenario['expected_verdict']}")
        print(f"  • Severity: {scenario['expected_verdict']}")
        print(f"  • PII Scrubbing: Configurable (default: false for internal Chronicle)")
    
    if "annotate_udm" in scenario["expected_actions"]:
        print_success("UDM Events Annotated: ANN-2026-005678")
        print(f"  • Annotation: AI triage result with MITRE mappings")
        print(f"  • PII Scrubbing: ALWAYS (long-term storage compliance)")
    
    if scenario["expected_verdict"] == "FALSE_POSITIVE":
        print_warning("No case created (false positive)")
        print(f"  • Action: Log only")
        print(f"  • Reason: {scenario['description']}")
    
    print()
    print_section("Demo Complete!")
    print_success(f"Scenario '{scenario['scenario']}' demonstrated successfully")
    print()


def run_interactive_demo():
    """Run interactive demo with scenario selection."""
    print_header("Chronicle Integration Demo")
    
    print("This demo showcases the Chronicle integration with realistic mock data.")
    print("No Chronicle credentials required - perfect for presentations!")
    print()
    
    scenarios = get_all_demo_scenarios()
    
    print("Available Scenarios:")
    print()
    for i, scenario in enumerate(scenarios, 1):
        print(f"{Colors.BOLD}{i}.{Colors.END} {scenario['scenario']}")
        print(f"   {scenario['description']}")
        print(f"   Expected: {scenario['expected_verdict']} (confidence: {scenario['expected_confidence'] * 100:.0f}%)")
        print()
    
    print(f"{Colors.BOLD}0.{Colors.END} Run all scenarios")
    print()
    
    choice = input(f"{Colors.BOLD}Select scenario (0-{len(scenarios)}):{Colors.END} ").strip()
    
    if choice == "0":
        for scenario in scenarios:
            run_scenario_demo(scenario)
            if scenario != scenarios[-1]:
                input(f"\n{Colors.BOLD}Press Enter for next scenario...{Colors.END}")
    elif choice.isdigit() and 1 <= int(choice) <= len(scenarios):
        scenario = scenarios[int(choice) - 1]
        run_scenario_demo(scenario)
    else:
        print_error("Invalid choice")
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Chronicle Integration Demo with realistic mock data"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Run specific scenario (e.g., high_confidence_idor)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all scenarios",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios",
    )
    
    args = parser.parse_args()
    
    if args.list:
        print_scenario_summary()
        sys.exit(0)
    
    scenarios = {s["scenario"]: s for s in get_all_demo_scenarios()}
    
    if args.scenario:
        if args.scenario not in scenarios:
            print_error(f"Unknown scenario: {args.scenario}")
            print(f"Available scenarios: {', '.join(scenarios.keys())}")
            sys.exit(1)
        
        run_scenario_demo(scenarios[args.scenario])
    
    elif args.all:
        for scenario in scenarios.values():
            run_scenario_demo(scenario)
            if list(scenarios.values())[-1] != scenario:
                input(f"\n{Colors.BOLD}Press Enter for next scenario...{Colors.END}")
    
    else:
        run_interactive_demo()


if __name__ == "__main__":
    main()
