#!/bin/bash
# Run all Chronicle demo scenarios

cd /home/mike/Documents/Cyber/llm-soc-triage

echo "=========================================="
echo "Chronicle Integration Demo Suite"
echo "=========================================="
echo ""
echo "Testing all 4 scenarios..."
echo ""

SCENARIOS=(
    "high_confidence_idor:High-Confidence IDOR Attack"
    "qa_testing_false_positive:QA Testing False Positive"
    "legitimate_customer_own_resources:Legitimate Customer Access"
    "insider_threat_employee:Insider Threat"
)

for scenario_full in "${SCENARIOS[@]}"; do
    IFS=: read -r scenario_id scenario_name <<< "$scenario_full"
    
    echo "=========================================="
    echo "Scenario: $scenario_name"
    echo "=========================================="
    
    # Generate alert for this scenario
    python3 << EOF
import hmac
import hashlib
import json
import sys
sys.path.insert(0, '.')

from tests.fixtures.chronicle_mock_data import get_all_demo_scenarios

scenarios = {s['scenario']: s for s in get_all_demo_scenarios()}
scenario = scenarios.get('$scenario_id')

if scenario:
    alert = scenario['alert']
    payload = json.dumps(alert, separators=(',', ':'), default=str)
    
    with open('/tmp/test_alert_$scenario_id.json', 'w') as f:
        f.write(payload)
    
    payload_bytes = payload.encode('utf-8')
    secret = "demo_webhook_secret"
    signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    
    with open('/tmp/sig_$scenario_id.txt', 'w') as f:
        f.write(signature)
    
    print(f"Expected: {scenario['expected_verdict']} ({scenario['expected_confidence']*100:.0f}% confidence)")
else:
    print("Scenario not found")
EOF
    
    SIG=$(cat /tmp/sig_$scenario_id.txt)
    
    # Send webhook
    curl -X POST http://localhost:8000/v1/chronicle/webhook \
      -H "Content-Type: application/json" \
      -H "X-Chronicle-Signature: sha256=$SIG" \
      -H "X-API-Key: test_api_key" \
      --data-binary "@/tmp/test_alert_$scenario_id.json" \
      -s \
      -o /tmp/response_$scenario_id.txt
    
    # Parse response
    python3 << PARSE
import json

scenario_id = "$scenario_id"

try:
    with open(f'/tmp/response_{scenario_id}.txt', 'r') as f:
        data = json.load(f)
    
    if data.get('success'):
        print(f"✓ SUCCESS")
        print(f"  Triage Result: {data.get('triage_result', 'N/A')}")
        print(f"  Confidence: {data.get('confidence', 0)*100:.0f}%")
        print(f"  Processing Time: {data.get('processing_time_ms', 0)}ms")
    else:
        error = data.get('error', 'Unknown error')
        # Truncate long errors
        if len(error) > 100:
            error = error[:100] + "..."
        print(f"✗ FAILED")
        print(f"  Error: {error}")
except FileNotFoundError:
    print(f"✗ Response file not found")
except json.JSONDecodeError as e:
    print(f"✗ Parse error: {e}")
    with open(f'/tmp/response_{scenario_id}.txt', 'r') as f:
        response = f.read()
    print(f"  Raw response (first 150 chars): {response[:150]}")
except Exception as e:
    print(f"✗ Unexpected error: {e}")
PARSE
    
    echo ""
    sleep 2
done

echo "=========================================="
echo "Demo Suite Complete"
echo "=========================================="
