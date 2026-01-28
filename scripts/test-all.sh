#!/bin/bash
# Comprehensive Test Suite - Validates all demo functionality

set -e

cd /home/mike/Documents/Cyber/llm-soc-triage

echo "=========================================="
echo "LLM SOC Triage - Comprehensive Test Suite"
echo "=========================================="
echo ""
echo "This script will:"
echo "  1. Verify all scripts are executable"
echo "  2. Check Docker services status"
echo "  3. Test middleware health endpoint"
echo "  4. Run Chronicle webhook test"
echo "  5. Validate response format"
echo ""
echo "Starting tests..."
echo ""

# Test 1: Verify scripts are executable
echo "TEST 1: Verifying script permissions..."
SCRIPTS=(
    "test-webhook-debug.sh"
    "test-webhook-simple.sh"
    "run-all-demos.sh"
    "start-demo.sh"
    "test-demo.sh"
    "test-chronicle-webhook.py"
)

for script in "${SCRIPTS[@]}"; do
    if [ -x "$script" ]; then
        echo "  ✓ $script is executable"
    else
        echo "  ✗ $script is NOT executable"
        exit 1
    fi
done
echo ""

# Test 2: Check if middleware is running
echo "TEST 2: Checking middleware status..."
if curl -s --connect-timeout 5 http://localhost:8000/health > /tmp/health_check.txt 2>&1; then
    echo "  ✓ Middleware is running"
    
    # Get health details
    MODEL=$(cat /tmp/health_check.txt | python3 -c "import json, sys; data=json.load(sys.stdin); print(data.get('configuration', {}).get('model', 'unknown'))" 2>/dev/null || echo "unknown")
    echo "  ✓ Model: $MODEL"
    
    # Verify it's responding correctly
    STATUS=$(cat /tmp/health_check.txt | python3 -c "import json, sys; data=json.load(sys.stdin); print(data.get('status', 'unknown'))" 2>/dev/null || echo "unknown")
    if [ "$STATUS" != "healthy" ]; then
        echo "  ⚠ Warning: Middleware status is '$STATUS'"
    fi
else
    echo "  ✗ Middleware is NOT running or not responding"
    echo ""
    echo "  Troubleshooting:"
    echo "    1. Check if containers are running: docker ps"
    echo "    2. Start services: sudo docker-compose up -d"
    echo "    3. Wait 30s for startup: sleep 30"
    echo "    4. Check logs: sudo docker logs llm-soc-triage-middleware"
    exit 1
fi
echo ""

# Test 3: Check API documentation
echo "TEST 3: Checking API documentation endpoints..."
if curl -s http://localhost:8000/docs > /dev/null 2>&1; then
    echo "  ✓ Swagger docs available at /docs"
else
    echo "  ✗ Swagger docs not available"
fi

if curl -s http://localhost:8000/redoc > /dev/null 2>&1; then
    echo "  ✓ ReDoc available at /redoc"
else
    echo "  ✗ ReDoc not available"
fi
echo ""

# Test 4: Run webhook test
echo "TEST 4: Testing Chronicle webhook..."
echo ""

# Generate test alert
python3 << 'EOF'
import hmac
import hashlib
import json
from tests.fixtures.chronicle_mock_data import get_mock_idor_alert

alert = get_mock_idor_alert(num_attempts=4, sequential=True)
payload = json.dumps(alert, separators=(',', ':'), default=str)

with open('/tmp/test_alert.json', 'w') as f:
    f.write(payload)

payload_bytes = payload.encode('utf-8')
secret = "demo_webhook_secret"
signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

with open('/tmp/test_signature.txt', 'w') as f:
    f.write(signature)

print(f"Alert: {alert['rule_name']}")
print(f"Events: {len(alert['udm_events'])}")
print(f"Signature: sha256={signature[:16]}...")
EOF

echo ""
SIG=$(cat /tmp/test_signature.txt)

# Send webhook request
HTTP_CODE=$(curl -X POST http://localhost:8000/v1/chronicle/webhook \
  -H "Content-Type: application/json" \
  -H "X-Chronicle-Signature: sha256=$SIG" \
  -H "X-API-Key: test_api_key" \
  --data-binary '@/tmp/test_alert.json' \
  -s -w "%{http_code}" \
  -o /tmp/test_response.txt)

echo "HTTP Status: $HTTP_CODE"
echo ""

# Parse response
python3 << 'PARSE'
import json
import sys

try:
    with open('/tmp/test_response.txt', 'r') as f:
        data = json.load(f)
    
    if data.get('success'):
        print("✓✓ WEBHOOK TEST PASSED!")
        print(f"  Alert ID: {data.get('alert_id', 'N/A')}")
        print(f"  Triage Result: {data.get('triage_result', 'N/A')}")
        print(f"  Confidence: {data.get('confidence', 0):.2f}")
        print(f"  Processing Time: {data.get('processing_time_ms', 0)}ms")
        sys.exit(0)
    else:
        print("✗✗ WEBHOOK TEST FAILED!")
        error = data.get('error', 'Unknown error')
        if len(error) > 200:
            error = error[:200] + "..."
        print(f"  Error: {error}")
        sys.exit(1)
        
except FileNotFoundError:
    print("✗✗ Response file not found!")
    sys.exit(1)
except json.JSONDecodeError as e:
    print("✗✗ INVALID JSON RESPONSE!")
    print(f"  Parse error: {e}")
    with open('/tmp/test_response.txt', 'r') as f:
        content = f.read()
    print(f"  Response (first 300 chars): {content[:300]}")
    sys.exit(1)
except Exception as e:
    print(f"✗✗ UNEXPECTED ERROR: {e}")
    sys.exit(1)
PARSE

WEBHOOK_RESULT=$?

echo ""
echo "=========================================="
if [ $WEBHOOK_RESULT -eq 0 ]; then
    echo "ALL TESTS PASSED ✓"
    echo "=========================================="
    echo ""
    echo "Your demo environment is ready!"
    echo ""
    echo "Next steps:"
    echo "  - Run: bash test-webhook-debug.sh (detailed webhook test)"
    echo "  - Run: bash run-all-demos.sh (test all scenarios)"
    echo "  - View logs: sudo docker-compose logs -f middleware"
    echo ""
    exit 0
else
    echo "TESTS FAILED ✗"
    echo "=========================================="
    echo ""
    echo "Troubleshooting:"
    echo "  - Check logs: sudo docker logs llm-soc-triage-middleware"
    echo "  - Verify API key: grep ANTHROPIC_API_KEY .env"
    echo "  - Restart services: sudo docker-compose restart"
    echo ""
    exit 1
fi
