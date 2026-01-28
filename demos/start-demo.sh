#!/bin/bash
# Start Demo Script - Run with: bash start-demo.sh

set -e

echo "=========================================="
echo "Starting llm-soc-triage Demo Environment"
echo "=========================================="
echo ""

# Check if running with sudo
if [ "$EUID" -eq 0 ]; then 
    echo "Running with sudo..."
else
    echo "Note: You may need to enter your sudo password"
fi

cd /home/mike/Documents/Cyber/llm-soc-triage

# Check API key
if ! grep -q "ANTHROPIC_API_KEY=sk-" .env; then
    echo "ERROR: ANTHROPIC_API_KEY not set in .env file"
    echo "Please edit .env and add your API key"
    exit 1
fi

echo "Step 1/4: Building Docker images (2-3 minutes)..."
sudo docker-compose build

echo ""
echo "Step 2/4: Starting services..."
sudo docker-compose up -d

echo ""
echo "Step 3/4: Waiting for services to be healthy (30 seconds)..."
sleep 30

echo ""
echo "Step 4/4: Running health checks..."
sudo docker-compose ps

echo ""
echo "=========================================="
echo "Demo Environment Ready!"
echo "=========================================="
echo ""
echo "Service URLs:"
echo "  - Middleware:     http://localhost:8000"
echo "  - Health Check:   http://localhost:8000/health"
echo "  - API Docs:       http://localhost:8000/docs"
echo "  - Chronicle Mock: http://localhost:8001"
echo ""
echo "Run a demo:"
echo "  curl -X POST http://localhost:8001/demo/trigger-webhook \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"scenario\": \"high_confidence_idor\", \"middleware_url\": \"http://middleware:8000\"}'"
echo ""
echo "View logs:"
echo "  sudo docker-compose logs -f"
echo ""
echo "Stop services:"
echo "  sudo docker-compose down"
echo ""
