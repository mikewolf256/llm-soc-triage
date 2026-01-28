#!/bin/bash
# Quick Test - Minimal script to validate webhook is working

cd /home/mike/Documents/Cyber/llm-soc-triage

echo "=========================================="
echo "Quick Chronicle Webhook Test"
echo "=========================================="
echo ""

# Step 1: Check if middleware is responding
echo "1. Checking middleware..."
if ! curl -s --connect-timeout 3 http://localhost:8000/health > /dev/null 2>&1; then
    echo "   ✗ Middleware not responding on port 8000"
    echo ""
    echo "   Start it with: sudo docker-compose up -d"
    exit 1
fi
echo "   ✓ Middleware is up"
echo ""

# Step 2: Generate test data
echo "2. Generating test alert..."
python3 -c "
import hmac, hashlib, json
from tests.fixtures.chronicle_mock_data import get_mock_idor_alert

alert = get_mock_idor_alert(num_attempts=4, sequential=True)
payload = json.dumps(alert, separators=(',', ':'), default=str)

with open('/tmp/quick_test_alert.json', 'w') as f:
    f.write(payload)

sig = hmac.new(b'demo_webhook_secret', payload.encode(), hashlib.sha256).hexdigest()
with open('/tmp/quick_test_sig.txt', 'w') as f:
    f.write(sig)

print(f'   Alert: {alert[\"rule_name\"]}')
print(f'   Events: {len(alert[\"udm_events\"])}')
"

if [ $? -ne 0 ]; then
    echo "   ✗ Failed to generate test data"
    exit 1
fi
echo ""

# Step 3: Send request
echo "3. Sending webhook request..."
SIG=$(cat /tmp/quick_test_sig.txt)

curl -X POST http://localhost:8000/v1/chronicle/webhook \
  -H "Content-Type: application/json" \
  -H "X-Chronicle-Signature: sha256=$SIG" \
  -H "X-API-Key: test_api_key" \
  --data-binary '@/tmp/quick_test_alert.json' \
  -s -o /tmp/quick_test_response.json \
  -w "   HTTP Status: %{http_code}\n"

if [ $? -ne 0 ]; then
    echo "   ✗ Curl failed"
    exit 1
fi
echo ""

# Step 4: Parse response
echo "4. Parsing response..."
python3 << 'PARSE'
import json
import sys

try:
    with open('/tmp/quick_test_response.json', 'r') as f:
        data = json.load(f)
    
    print(json.dumps(data, indent=2))
    print("")
    
    if data.get('success'):
        print("✓✓ TEST PASSED!")
        print(f"   Triage: {data.get('triage_result')}")
        print(f"   Confidence: {data.get('confidence')}")
        print(f"   Processing: {data.get('processing_time_ms')}ms")
        sys.exit(0)
    else:
        print("✗✗ TEST FAILED!")
        print(f"   Error: {data.get('error', 'Unknown')}")
        sys.exit(1)
        
except FileNotFoundError:
    print("✗✗ Response file not found")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"✗✗ Invalid JSON: {e}")
    with open('/tmp/quick_test_response.json', 'r') as f:
        print(f"   Raw response: {f.read()[:200]}")
    sys.exit(1)
except Exception as e:
    print(f"✗✗ Error: {e}")
    sys.exit(1)
PARSE

echo ""
echo "=========================================="
