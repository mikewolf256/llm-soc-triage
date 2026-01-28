# Quick Start Guide - Docker Demo Environment

## Setup (Without Make)

If `make` is not installed, use these commands directly:

### 1. Initial Setup

```bash
# Navigate to project
cd /home/mike/Documents/Cyber/llm-soc-triage

# Create .env file from template
cp .env.docker .env

# Edit .env and add your Anthropic API key
nano .env
# Or use your preferred editor:
# vim .env
# code .env
```

**REQUIRED**: Set your Anthropic API key in `.env`:
```bash
ANTHROPIC_API_KEY=your_actual_api_key_here
```

### 2. Build Docker Images

```bash
# Build all images
docker-compose build

# Or build with no cache
docker-compose build --no-cache
```

### 3. Start Services

```bash
# Start in background
docker-compose up -d

# Or start with logs visible
docker-compose up
```

### 4. Verify Health

```bash
# Check container status
docker-compose ps

# Check middleware health
curl http://localhost:8000/health | jq

# Check Chronicle mock health
curl http://localhost:8001/ | jq

# Check Redis
docker exec llm-soc-triage-redis redis-cli ping
```

---

## Running Demos

### Trigger Chronicle Webhook

```bash
# High-confidence IDOR attack
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "high_confidence_idor", "middleware_url": "http://middleware:8000"}'

# QA testing false positive
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "qa_testing_false_positive", "middleware_url": "http://middleware:8000"}'

# Insider threat
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "insider_threat_employee", "middleware_url": "http://middleware:8000"}'
```

### View Results

```bash
# View middleware logs
docker-compose logs -f middleware

# View Chronicle mock logs
docker-compose logs -f chronicle-mock

# View created cases
curl http://localhost:8001/demo/cases | jq

# View UDM annotations
curl http://localhost:8001/demo/annotations | jq
```

---

## Common Commands

### Service Management

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs (all services)
docker-compose logs -f

# View specific service logs
docker-compose logs -f middleware
docker-compose logs -f chronicle-mock
docker-compose logs -f redis
```

### Shell Access

```bash
# Open shell in middleware container
docker exec -it llm-soc-triage-middleware /bin/bash

# Open Redis CLI
docker exec -it llm-soc-triage-redis redis-cli

# Open shell in Chronicle mock
docker exec -it llm-soc-triage-chronicle-mock /bin/bash
```

### Testing

```bash
# Test middleware
curl http://localhost:8000/health | jq

# Test Chronicle mock
curl http://localhost:8001/demo/scenarios | jq

# Run pytest in container
docker exec llm-soc-triage-middleware pytest tests/ -v
```

### Cleanup

```bash
# Stop and remove containers
docker-compose down

# Stop and remove containers + volumes
docker-compose down -v

# Remove everything and rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

---

## Service URLs

| Service | URL | Description |
|---------|-----|-------------|
| Middleware API | http://localhost:8000 | Main triage endpoint |
| Health Check | http://localhost:8000/health | Service health |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Chronicle Mock | http://localhost:8001 | Mock Chronicle API |
| Demo Scenarios | http://localhost:8001/demo/scenarios | Available demos |
| Redis | localhost:6379 | Direct connection |

---

## Troubleshooting

### Containers Won't Start

```bash
# Check status
docker-compose ps

# Check logs
docker-compose logs

# Check specific service
docker-compose logs middleware
```

### Port Already in Use

```bash
# Find process using port
lsof -i :8000
lsof -i :8001
lsof -i :6379

# Or change ports in docker-compose.yml
```

### Rebuild Everything

```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### View Resource Usage

```bash
docker stats
```

---

## With Make (If Installed)

If you have `make` installed, you can use these shortcuts:

```bash
make setup      # Initial setup
make build      # Build images
make up         # Start services
make down       # Stop services
make logs       # View logs
make demo       # Run demo
make test       # Run tests
make health     # Check health
make clean      # Full cleanup
make help       # Show all commands
```

---

## Next Steps

1. **Verify Setup**: Run `docker-compose ps` to see all services running
2. **Run Demo**: Trigger a webhook and watch the logs
3. **Explore API**: Visit http://localhost:8000/docs for Swagger UI
4. **Read Docs**: Check `docs/DOCKER_SETUP.md` for detailed guide

Questions? See `docs/DOCKER_SETUP.md` for comprehensive documentation.
