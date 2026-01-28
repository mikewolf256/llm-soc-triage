# Makefile for llm-soc-triage Docker Demo Environment
# 
# Common commands:
#   make setup    - Initial setup (copy env file)
#   make build    - Build Docker images
#   make up       - Start all services
#   make down     - Stop all services
#   make logs     - View logs
#   make demo     - Run Chronicle demo
#   make test     - Run integration tests

.PHONY: help setup build up down restart logs logs-middleware logs-chronicle demo test clean

help:
	@echo "llm-soc-triage Docker Demo Environment"
	@echo ""
	@echo "Available commands:"
	@echo "  make setup          - Initial setup (copy .env file)"
	@echo "  make build          - Build Docker images"
	@echo "  make up             - Start all services"
	@echo "  make down           - Stop all services"
	@echo "  make restart        - Restart all services"
	@echo "  make logs           - View logs (all services)"
	@echo "  make logs-middleware - View middleware logs only"
	@echo "  make logs-chronicle  - View Chronicle mock logs only"
	@echo "  make demo           - Run Chronicle demo scenarios"
	@echo "  make test           - Run integration tests"
	@echo "  make shell-middleware - Open shell in middleware container"
	@echo "  make shell-redis    - Open Redis CLI"
	@echo "  make health         - Check health of all services"
	@echo "  make clean          - Stop and remove containers, volumes"
	@echo "  make rebuild        - Clean build and restart"

# Setup
setup:
	@echo "Setting up Docker environment..."
	@if [ ! -f .env ]; then \
		cp .env.docker .env; \
		echo "✓ Created .env file from .env.docker"; \
		echo "⚠  IMPORTANT: Edit .env and add your ANTHROPIC_API_KEY"; \
	else \
		echo "✓ .env file already exists"; \
	fi
	@mkdir -p logs
	@echo "✓ Setup complete"

# Build images
build:
	@echo "Building Docker images..."
	docker-compose build --no-cache
	@echo "✓ Build complete"

# Start services
up:
	@echo "Starting services..."
	docker-compose up -d
	@echo ""
	@echo "✓ Services started"
	@echo ""
	@echo "Access points:"
	@echo "  - Middleware:      http://localhost:8000"
	@echo "  - Health check:    http://localhost:8000/health"
	@echo "  - Chronicle Mock:  http://localhost:8001"
	@echo "  - Redis:           localhost:6379"
	@echo ""
	@echo "View logs: make logs"
	@echo "Run demo:  make demo"

# Start with logs
up-logs:
	@echo "Starting services with logs..."
	docker-compose up

# Stop services
down:
	@echo "Stopping services..."
	docker-compose down
	@echo "✓ Services stopped"

# Restart services
restart: down up

# View logs
logs:
	docker-compose logs -f

logs-middleware:
	docker-compose logs -f middleware

logs-chronicle:
	docker-compose logs -f chronicle-mock

logs-redis:
	docker-compose logs -f redis

# Run Chronicle demo
demo:
	@echo "Running Chronicle demo scenarios..."
	@echo ""
	@echo "Available scenarios:"
	@echo "  1. High-confidence IDOR attack"
	@echo "  2. QA testing false positive"
	@echo "  3. Legitimate customer access"
	@echo "  4. Insider threat"
	@echo ""
	@docker exec -it llm-soc-triage-chronicle-mock python chronicle_mock_server.py --help || true
	@echo ""
	@echo "Trigger webhook:"
	@curl -X POST http://localhost:8001/demo/trigger-webhook \
		-H "Content-Type: application/json" \
		-d '{"scenario": "high_confidence_idor", "middleware_url": "http://middleware:8000"}' \
		2>/dev/null | python -m json.tool || echo "Demo webhook triggered"

# Integration tests
test:
	@echo "Running integration tests..."
	@echo ""
	@echo "Testing middleware health..."
	@curl -s http://localhost:8000/health | python -m json.tool
	@echo ""
	@echo "Testing Chronicle mock health..."
	@curl -s http://localhost:8001/ | python -m json.tool
	@echo ""
	@echo "Testing Redis connection..."
	@docker exec llm-soc-triage-redis redis-cli ping
	@echo ""
	@echo "✓ All services healthy"

# Shell access
shell-middleware:
	docker exec -it llm-soc-triage-middleware /bin/bash

shell-chronicle:
	docker exec -it llm-soc-triage-chronicle-mock /bin/bash

shell-redis:
	docker exec -it llm-soc-triage-redis redis-cli

# Health checks
health:
	@echo "Checking service health..."
	@echo ""
	@echo "Middleware:"
	@curl -s http://localhost:8000/health | python -m json.tool || echo "  ✗ Middleware unhealthy"
	@echo ""
	@echo "Chronicle Mock:"
	@curl -s http://localhost:8001/ | python -m json.tool || echo "  ✗ Chronicle Mock unhealthy"
	@echo ""
	@echo "Redis:"
	@docker exec llm-soc-triage-redis redis-cli ping || echo "  ✗ Redis unhealthy"
	@echo ""
	@docker-compose ps

# Clean up
clean:
	@echo "Cleaning up Docker environment..."
	docker-compose down -v --remove-orphans
	@echo "✓ Cleanup complete"

# Rebuild from scratch
rebuild: clean build up
	@echo "✓ Rebuild complete"

# View resource usage
stats:
	docker stats --no-stream
