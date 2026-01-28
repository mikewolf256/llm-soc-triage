#!/bin/bash
# Debug environment configuration

echo "=========================================="
echo "Environment Debug"
echo "=========================================="
echo ""

cd /home/mike/Documents/Cyber/llm-soc-triage

echo "1. Current .env file MODEL_NAME:"
grep MODEL_NAME .env
echo ""

echo "2. Container MODEL_NAME:"
sudo docker exec llm-soc-triage-middleware env | grep MODEL_NAME
echo ""

echo "3. Middleware health endpoint shows:"
curl -s http://localhost:8000/health | grep -o '"model":"[^"]*"'
echo ""
echo ""

echo "=========================================="
echo "FIX: The container needs to be STOPPED and STARTED (not just restarted)"
echo "=========================================="
echo ""
echo "Run these commands:"
echo "  sudo docker-compose down"
echo "  sudo docker-compose up -d"
echo "  sleep 20"
echo "  bash test-webhook-debug.sh"
echo ""
