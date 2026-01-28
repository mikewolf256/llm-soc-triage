#!/bin/bash
# Test Demo Script - Run with: bash test-demo.sh

echo "=========================================="
echo "Testing llm-soc-triage Demo Environment"
echo "=========================================="
echo ""

cd /home/mike/Documents/Cyber/llm-soc-triage

# Check container status
echo "1. Checking container status..."
sudo docker-compose ps
echo ""

# Check middleware logs (last 20 lines)
echo "2. Middleware logs (last 20 lines)..."
sudo docker logs llm-soc-triage-middleware 2>&1 | tail -20
echo ""

# Check Chronicle mock logs (last 10 lines)
echo "3. Chronicle mock logs (last 10 lines)..."
sudo docker logs llm-soc-triage-chronicle-mock 2>&1 | tail -10
echo ""

# Test Chronicle mock API
echo "4. Testing Chronicle Mock API..."
curl -s http://localhost:8001/ | python3 -m json.tool | head -15
echo ""

# Test middleware health
echo "5. Testing Middleware Health..."
curl -s http://localhost:8000/health 2>&1
echo ""
echo ""

# If middleware is up, run a demo
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "6. Middleware is UP! Running demo..."
    echo ""
    curl -X POST http://localhost:8001/demo/trigger-webhook \
      -H "Content-Type: application/json" \
      -d '{"scenario": "high_confidence_idor", "middleware_url": "http://middleware:8000"}' \
      2>/dev/null | python3 -m json.tool
    echo ""
    
    echo "7. Checking created cases..."
    curl -s http://localhost:8001/demo/cases | python3 -m json.tool
    echo ""
else
    echo "6. Middleware is DOWN or starting up"
    echo "   Check logs above for errors"
    echo ""
    echo "Common issues:"
    echo "  - Missing ANTHROPIC_API_KEY in .env"
    echo "  - Container still starting (wait 30-60s)"
    echo "  - Port 8000 already in use"
    echo "  - Check: sudo docker logs llm-soc-triage-middleware"
fi

echo "=========================================="
echo "Test Complete"
echo "=========================================="
