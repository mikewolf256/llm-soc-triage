"""
Copyright (c) 2026 Agentic Security Partners LLC. All Rights Reserved.

Mock Chronicle API Server for Demos

Runs a local FastAPI server that simulates Chronicle API endpoints.
Use this for demos, development, and integration testing.

Usage:
    # Start mock server
    python tests/fixtures/chronicle_mock_server.py
    
    # Server runs at http://localhost:8001
    # Configure middleware to use mock Chronicle:
    export CHRONICLE_REGION=us
    export CHRONICLE_CREDENTIALS_FILE=/tmp/mock_creds.json
    
    # Then trigger webhook
    curl -X POST http://localhost:8000/v1/chronicle/webhook \
      -H "Content-Type: application/json" \
      -d @tests/fixtures/sample_alert.json
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import hashlib
import hmac
import json
from typing import Dict, Any, Optional
from datetime import datetime

from chronicle_mock_data import (
    get_mock_prevalence_response,
    get_mock_user_baseline_response,
    get_mock_network_context_response,
    get_mock_idor_alert,
    get_all_demo_scenarios,
)


# Create FastAPI app
app = FastAPI(
    title="Chronicle Mock API Server",
    description="Mock Chronicle API for demos and testing",
    version="1.0.0",
)

# Enable CORS for browser testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock data store (in-memory for simplicity)
mock_cases = {}
mock_annotations = {}


@app.get("/")
async def root():
    """Health check and info endpoint."""
    return {
        "service": "Chronicle Mock API",
        "status": "healthy",
        "version": "1.0.0",
        "endpoints": {
            "prevalence": "/v2/ioc/prevalence",
            "user_baseline": "/v2/users/{user_id}/baseline",
            "network_context": "/v2/network/{ip_address}",
            "udm_search": "/v2/udm/search",
            "cases": "/v2/cases",
            "udm_annotate": "/v2/udm/annotate",
            "webhook_trigger": "/demo/trigger-webhook",
        },
        "demo_scenarios": [s["scenario"] for s in get_all_demo_scenarios()],
    }


# ============================================================================
# Chronicle API Endpoints (Mocked)
# ============================================================================

@app.get("/v2/ioc/prevalence")
async def get_ioc_prevalence(
    indicator: str,
    indicator_type: str = "hash",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Mock Chronicle IOC prevalence endpoint.
    
    Returns: Asset prevalence data for IOC.
    """
    # Simulate different prevalence based on indicator
    if "known" in indicator.lower():
        affected_count = 47  # Widespread
    elif "rare" in indicator.lower():
        affected_count = 3  # Uncommon
    elif "new" in indicator.lower():
        affected_count = 0  # Never seen
    else:
        # Random for realism
        import random
        affected_count = random.choice([0, 1, 3, 5, 12, 47])
    
    return get_mock_prevalence_response(indicator, indicator_type, affected_count)


@app.get("/v2/users/{user_id}/baseline")
async def get_user_baseline(
    user_id: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Mock Chronicle user baseline endpoint.
    
    Returns: User behavior baseline.
    """
    # Determine if user is normal based on ID
    is_normal = "qa" not in user_id.lower() and "attacker" not in user_id.lower()
    
    return get_mock_user_baseline_response(user_id, is_normal)


@app.get("/v2/network/{ip_address}")
async def get_network_context(
    ip_address: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Mock Chronicle network context endpoint.
    
    Returns: Network intelligence for IP.
    """
    # Determine if IP is known
    is_known = ip_address.startswith("10.") or ip_address.startswith("172.16.")
    
    return get_mock_network_context_response(ip_address, is_known)


@app.post("/v2/udm/search")
async def search_udm(request: Dict[str, Any]):
    """
    Mock Chronicle UDM search endpoint.
    
    Returns: Sample UDM events.
    """
    query = request.get("query", "")
    max_results = request.get("max_results", 10)
    
    # Return sample IDOR alert UDM events
    alert = get_mock_idor_alert(num_attempts=min(max_results, 5))
    
    return {
        "events": alert["udm_events"],
        "total_count": len(alert["udm_events"]),
        "query": query,
    }


@app.post("/v2/cases")
async def create_case(case_data: Dict[str, Any]):
    """
    Mock Chronicle case creation endpoint.
    
    Returns: Created case ID.
    """
    import uuid
    
    case_id = f"CHR-2026-{len(mock_cases) + 1:06d}"
    case_url = f"https://us.chronicle.security/cases/{case_id}"
    
    # Store case
    mock_cases[case_id] = {
        "case_id": case_id,
        "case_url": case_url,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "data": case_data,
    }
    
    print(f"[MOCK_CHRONICLE] Case created: {case_id}")
    print(f"  Title: {case_data.get('title', 'N/A')}")
    print(f"  Severity: {case_data.get('severity', 'N/A')}")
    
    return {
        "case_id": case_id,
        "case_url": case_url,
        "success": True,
    }


@app.post("/v2/udm/annotate")
async def annotate_udm(annotation_data: Dict[str, Any]):
    """
    Mock Chronicle UDM annotation endpoint.
    
    Returns: Annotation ID.
    """
    import uuid
    
    annotation_id = f"ANN-2026-{len(mock_annotations) + 1:06d}"
    event_id = annotation_data.get("event_id")
    
    # Store annotation
    mock_annotations[annotation_id] = {
        "annotation_id": annotation_id,
        "event_id": event_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "data": annotation_data,
    }
    
    print(f"[MOCK_CHRONICLE] UDM annotation created: {annotation_id}")
    print(f"  Event ID: {event_id}")
    print(f"  Type: {annotation_data.get('annotation_type', 'N/A')}")
    
    return {
        "annotation_id": annotation_id,
        "event_id": event_id,
        "success": True,
    }


# ============================================================================
# Demo Helper Endpoints
# ============================================================================

@app.get("/demo/scenarios")
async def get_demo_scenarios():
    """
    Get all available demo scenarios.
    
    Returns: List of demo scenarios with descriptions.
    """
    scenarios = get_all_demo_scenarios()
    
    return {
        "scenarios": [
            {
                "id": s["scenario"],
                "description": s["description"],
                "expected_verdict": s["expected_verdict"],
                "expected_confidence": s["expected_confidence"],
            }
            for s in scenarios
        ]
    }


@app.post("/demo/trigger-webhook")
async def trigger_webhook(
    scenario: str = "high_confidence_idor",
    middleware_url: str = "http://localhost:8000",
):
    """
    Trigger middleware webhook with demo scenario.
    
    Args:
        scenario: Which demo scenario to use
        middleware_url: Middleware base URL
    
    Returns: Webhook trigger result
    """
    import httpx
    
    # Get scenario data
    scenarios = {s["scenario"]: s for s in get_all_demo_scenarios()}
    
    if scenario not in scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario: {scenario}. Available: {list(scenarios.keys())}"
        )
    
    scenario_data = scenarios[scenario]
    alert = scenario_data["alert"]
    
    # Compute webhook signature (mock)
    webhook_secret = "test_secret_key"
    payload = json.dumps(alert).encode()
    signature = hmac.new(webhook_secret.encode(), payload, hashlib.sha256).hexdigest()
    
    # Send to middleware
    webhook_url = f"{middleware_url}/v1/chronicle/webhook"
    
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                webhook_url,
                json=alert,
                headers={
                    "Content-Type": "application/json",
                    "X-Chronicle-Signature": f"sha256={signature}",
                    "Authorization": "Bearer demo_api_key",
                }
            )
            response.raise_for_status()
            result = response.json()
        
        return {
            "success": True,
            "scenario": scenario,
            "webhook_url": webhook_url,
            "middleware_response": result,
        }
    
    except Exception as e:
        return {
            "success": False,
            "scenario": scenario,
            "error": str(e),
        }


@app.get("/demo/cases")
async def get_mock_cases():
    """Get all mock cases created."""
    return {
        "total_cases": len(mock_cases),
        "cases": list(mock_cases.values()),
    }


@app.get("/demo/annotations")
async def get_mock_annotations():
    """Get all mock UDM annotations created."""
    return {
        "total_annotations": len(mock_annotations),
        "annotations": list(mock_annotations.values()),
    }


# ============================================================================
# Server Startup
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Chronicle Mock API Server")
    print("=" * 70)
    print()
    print("Starting server at: http://localhost:8001")
    print()
    print("Available Endpoints:")
    print("  - GET  /                        - Health check and info")
    print("  - GET  /demo/scenarios          - List demo scenarios")
    print("  - POST /demo/trigger-webhook    - Trigger middleware webhook")
    print("  - GET  /demo/cases              - View created cases")
    print("  - GET  /demo/annotations        - View UDM annotations")
    print()
    print("Chronicle API Endpoints (Mocked):")
    print("  - GET  /v2/ioc/prevalence       - IOC prevalence")
    print("  - GET  /v2/users/{id}/baseline  - User baseline")
    print("  - GET  /v2/network/{ip}         - Network context")
    print("  - POST /v2/udm/search           - UDM search")
    print("  - POST /v2/cases                - Create case")
    print("  - POST /v2/udm/annotate         - Annotate UDM")
    print()
    print("=" * 70)
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
