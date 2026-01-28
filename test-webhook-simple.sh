#!/bin/bash
# Simple Chronicle webhook test using curl

cd /home/mike/Documents/Cyber/llm-soc-triage

echo "=========================================="
echo "Chronicle Webhook Test"
echo "=========================================="
echo ""

# Generate test alert using Python
python3 << 'EOF'
import hmac
import hashlib
import json
from tests.fixtures.chronicle_mock_data import get_mock_idor_alert

# Generate alert
alert = get_mock_idor_alert(num_attempts=4, sequential=True)

# Serialize to JSON (compact)
payload = json.dumps(alert, separators=(',', ':'), default=str)

# Write to file
with open('/tmp/chronicle_test_alert.json', 'w') as f:
    f.write(payload)

# Compute signature
payload_bytes = payload.encode('utf-8')
secret = "demo_webhook_secret"
signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

# Write signature to file
with open('/tmp/chronicle_signature.txt', 'w') as f:
    f.write(f"sha256={signature}")

print(f"Alert: {alert['rule_name']}")
print(f"Distinct resources: {alert['distinct_resources']}")
print(f"Signature: sha256={signature}")
EOF

echo ""
echo "Sending to middleware..."
echo ""

SIGNATURE=$(cat /tmp/chronicle_signature.txt)

HTTP_STATUS=$(curl -X POST http://localhost:8000/v1/chronicle/webhook \
  -H "Content-Type: application/json" \
  -H "X-Chronicle-Signature: $SIGNATURE" \
  -H "X-API-Key: test_api_key" \
  --data-binary '@/tmp/chronicle_test_alert.json' \
  -w "%{http_code}" \
  -s \
  -o /tmp/simple_response.txt)

python3 << 'PARSE_SCRIPT'
import sys
import json

try:
    with open('/tmp/simple_response.txt', 'r') as f:
        data = json.load(f)
    
    print(json.dumps(data, indent=2))
    
    if data.get('success'):
        print(f"\n✓ Success! Triage: {data.get('triage_result')} (confidence: {data.get('confidence')})")
    else:
        print(f"\n✗ Failed: {data.get('error')}")
except FileNotFoundError:
    print("✗ Response file not found")
except json.JSONDecodeError as e:
    print(f"✗ Invalid JSON response: {e}")
    with open('/tmp/simple_response.txt', 'r') as f:
        body = f.read()
    print(f"Raw response: {body[:500]}")
except Exception as e:
    print(f"✗ Error: {e}")
PARSE_SCRIPT

echo ""
echo "Status: $HTTP_STATUS"
PARSE_SCRIPT

echo ""
echo "=========================================="
echo "Test Complete"
echo "=========================================="
