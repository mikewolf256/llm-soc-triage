#!/bin/bash
# Debug Chronicle webhook with detailed output

cd /home/mike/Documents/Cyber/llm-soc-triage

echo "=========================================="
echo "Chronicle Webhook Debug Test"
echo "=========================================="
echo ""

# Generate test alert
python3 << 'EOF'
import hmac
import hashlib
import json
from tests.fixtures.chronicle_mock_data import get_mock_idor_alert

alert = get_mock_idor_alert(num_attempts=4, sequential=True)
payload = json.dumps(alert, separators=(',', ':'), default=str)
with open('/tmp/chronicle_test_alert.json', 'w') as f:
    f.write(payload)

payload_bytes = payload.encode('utf-8')
secret = "demo_webhook_secret"
signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
with open('/tmp/signature.txt', 'w') as f:
    f.write(signature)

print(f"Alert: {alert['rule_name']}")
print(f"Distinct resources: {alert['distinct_resources']}")
print(f"Payload size: {len(payload)} bytes")
print(f"Signature: sha256={signature}")
EOF

echo ""
echo "Sending request..."
echo ""

SIG=$(cat /tmp/signature.txt)

# Save response to file
curl -X POST http://localhost:8000/v1/chronicle/webhook \
  -H "Content-Type: application/json" \
  -H "X-Chronicle-Signature: sha256=$SIG" \
  -H "X-API-Key: test_api_key" \
  --data-binary '@/tmp/chronicle_test_alert.json' \
  -s -w "\n\n===HTTP_STATUS:%{http_code}===\n" \
  -o /tmp/response.txt

echo "Response saved to /tmp/response.txt"
echo ""
echo "--- RAW RESPONSE ---"
cat /tmp/response.txt
echo ""
echo "--- END RAW RESPONSE ---"
echo ""

# Try to parse as JSON
echo "Attempting JSON parse..."
python3 << 'EOF'
import json

with open('/tmp/response.txt', 'r') as f:
    content = f.read()

print(f"Response length: {len(content)} bytes")
print(f"First 200 chars: {content[:200]}")
print()

# Try to find where JSON ends
lines = content.split('\n')
print(f"Response has {len(lines)} lines")

# Try parsing just the JSON part
try:
    # Find JSON object
    json_end = content.find('}') + 1
    if json_end > 0:
        json_part = content[:json_end]
        data = json.loads(json_part)
        print("\n✓ Successfully parsed JSON:")
        print(json.dumps(data, indent=2))
        
        if data.get('success'):
            print("\n✓✓ Chronicle webhook SUCCEEDED!")
            print(f"   Triage result: {data.get('triage_result')}")
            print(f"   Confidence: {data.get('confidence')}")
        else:
            print(f"\n✗ Chronicle webhook returned error:")
            print(f"   Error: {data.get('error')}")
    else:
        print("✗ No JSON object found in response")
        
except json.JSONDecodeError as e:
    print(f"\n✗ JSON parse error: {e}")
    print(f"   Error at position {e.pos}")
    if e.pos < len(content):
        print(f"   Character at error: {repr(content[e.pos:e.pos+20])}")
except Exception as e:
    print(f"\n✗ Unexpected error: {e}")
EOF

echo ""
echo "=========================================="
