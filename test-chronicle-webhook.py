#!/usr/bin/env python3
"""
Test Chronicle webhook endpoint with proper signature.
"""

import httpx
import hmac
import hashlib
import json
import asyncio
from tests.fixtures.chronicle_mock_data import get_mock_idor_alert


async def test_webhook():
    # Generate alert
    alert = get_mock_idor_alert(num_attempts=4, sequential=True)
    
    # Serialize to JSON
    payload = json.dumps(alert, default=str)
    payload_bytes = payload.encode('utf-8')
    
    # Compute HMAC signature
    secret = "demo_webhook_secret"
    signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    
    print("=" * 70)
    print("Testing Chronicle Webhook Endpoint")
    print("=" * 70)
    print(f"\nAlert: {alert['rule_name']}")
    print(f"Severity: {alert['severity']}")
    print(f"Distinct resources: {alert['distinct_resources']}")
    print(f"UDM events: {len(alert['udm_events'])}")
    print(f"\nSignature: sha256={signature}")
    print(f"Secret: {secret}")
    print()
    
    # Send to middleware
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            response = await client.post(
                "http://localhost:8000/v1/chronicle/webhook",
                content=payload_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-Chronicle-Signature": f"sha256={signature}",
                    "X-API-Key": "test_api_key",
                }
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"\nResponse:")
            print(json.dumps(response.json(), indent=2, default=str))
            
            if response.status_code == 200:
                print("\n✓ Chronicle webhook test PASSED!")
            else:
                print(f"\n✗ Chronicle webhook test FAILED: {response.status_code}")
        
        except Exception as e:
            print(f"\n✗ Request failed: {e}")


if __name__ == "__main__":
    asyncio.run(test_webhook())
