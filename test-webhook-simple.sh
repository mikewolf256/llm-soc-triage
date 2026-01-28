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

curl -X POST http://localhost:8000/v1/chronicle/webhook \
  -H "Content-Type: application/json" \
  -H "X-Chronicle-Signature: $SIGNATURE" \
  -H "X-API-Key: test_api_key" \
  --data-binary '@/tmp/chronicle_test_alert.json' \
  -w "\n\nStatus: %{http_code}\n" \
  -s | python3 -m json.tool

echo ""
echo "=========================================="
echo "Test Complete"
echo "=========================================="
