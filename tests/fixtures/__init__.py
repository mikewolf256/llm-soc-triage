"""
Test fixtures for Chronicle integration demos and testing.
"""

from .chronicle_mock_data import (
    get_mock_udm_event,
    get_mock_idor_alert,
    get_mock_prevalence_response,
    get_mock_user_baseline_response,
    get_mock_network_context_response,
    get_demo_scenario_high_confidence_idor,
    get_demo_scenario_qa_testing,
    get_demo_scenario_legitimate_customer,
    get_demo_scenario_insider_threat,
    get_all_demo_scenarios,
)

__all__ = [
    "get_mock_udm_event",
    "get_mock_idor_alert",
    "get_mock_prevalence_response",
    "get_mock_user_baseline_response",
    "get_mock_network_context_response",
    "get_demo_scenario_high_confidence_idor",
    "get_demo_scenario_qa_testing",
    "get_demo_scenario_legitimate_customer",
    "get_demo_scenario_insider_threat",
    "get_all_demo_scenarios",
]
