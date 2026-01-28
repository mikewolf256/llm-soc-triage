# Docker Production Demo Environment

## Overview

This Docker Compose setup provides a production-ready demo environment for the `llm-soc-triage` middleware with:
- Full middleware stack (FastAPI + Redis + Mock Chronicle)
- Health checks and monitoring
- Production-like networking and security
- One-command startup (`make up`)
- Perfect for demos, development, and integration testing

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network (172.28.0.0/16)           │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │              │    │              │    │              │  │
│  │  Middleware  │◄───┤    Redis     │    │  Chronicle   │  │
│  │   (8000)     │    │   (6379)     │    │    Mock      │  │
│  │              │    │              │    │   (8001)     │  │
│  └──────┬───────┘    └──────────────┘    └──────┬───────┘  │
│         │                                        │          │
└─────────┼────────────────────────────────────────┼──────────┘
          │                                        │
          ▼                                        ▼
     Port 8000                                Port 8001
   (Host Access)                            (Host Access)
```

### Services

**1. Middleware** (`llm-soc-triage-middleware`)
- Main FastAPI application
- Handles alert triage with LLM
- Performs PII scrubbing
- Integrates with Chronicle
- Port: `8000`

**2. Redis** (`llm-soc-triage-redis`)
- Stateful IDOR tracking
- Session management
- Caching layer
- Port: `6379`
- Persistence: Volume-backed with AOF

**3. Chronicle Mock** (`llm-soc-triage-chronicle-mock`)
- Simulates Chronicle API
- Provides realistic UDM events
- No credentials required
- Port: `8001`

---

## Quick Start (5 Minutes)

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Make (optional, but recommended)

Check installation:
```bash
docker --version
docker-compose --version
make --version
```

### Setup

```bash
# 1. Initial setup (creates .env file)
make setup

# 2. Edit .env and add your Anthropic API key
nano .env
# Set: ANTHROPIC_API_KEY=your_actual_api_key_here

# 3. Build images
make build

# 4. Start services
make up

# 5. Verify health
make health
```

Your production demo environment is now running.

---

## Service Access

Once running, access services at:

| Service | URL | Description |
|---------|-----|-------------|
| **Middleware** | http://localhost:8000 | Main API endpoint |
| **Health Check** | http://localhost:8000/health | Service health status |
| **API Docs** | http://localhost:8000/docs | FastAPI Swagger UI |
| **Chronicle Mock** | http://localhost:8001 | Mock Chronicle API |
| **Chronicle Demo** | http://localhost:8001/demo/scenarios | Demo scenarios list |
| **Redis** | localhost:6379 | Redis server (CLI: `make shell-redis`) |

---

## Common Commands

### Service Management

```bash
# Start services
make up

# Stop services
make down

# Restart services
make restart

# View logs (all services)
make logs

# View middleware logs only
make logs-middleware

# View Chronicle mock logs only
make logs-chronicle
```

### Demo and Testing

```bash
# Run Chronicle demo
make demo

# Run integration tests
make test

# Check service health
make health

# View resource usage
make stats
```

### Shell Access

```bash
# Open shell in middleware container
make shell-middleware

# Open Redis CLI
make shell-redis

# Open shell in Chronicle mock container
make shell-chronicle
```

### Cleanup

```bash
# Stop and remove containers
make down

# Stop and remove containers + volumes
make clean

# Rebuild from scratch
make rebuild
```

---

## Running Chronicle Demos

### Method 1: Trigger Webhook via cURL

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

### Method 2: View Chronicle Mock Cases

```bash
# View created cases
curl http://localhost:8001/demo/cases | jq

# View UDM annotations
curl http://localhost:8001/demo/annotations | jq
```

### Method 3: Direct API Testing

```bash
# Test middleware health
curl http://localhost:8000/health | jq

# Test Chronicle mock API
curl http://localhost:8001/v2/ioc/prevalence?indicator=abc123hash | jq

# Test user baseline
curl http://localhost:8001/v2/users/user_12345/baseline | jq

# Test network context
curl http://localhost:8001/v2/network/203.0.113.100 | jq
```

---

## Configuration

### Environment Variables

Edit `.env` to configure the demo environment:

```bash
# Anthropic API (REQUIRED)
ANTHROPIC_API_KEY=your_api_key_here

# IDOR Detection Settings
IDOR_THRESHOLD=3           # Min distinct resources
IDOR_TIME_WINDOW=60        # Window in seconds
IDOR_REDIS_TTL=300         # Redis TTL

# Chronicle Integration
CHRONICLE_CONTEXT_ENRICHMENT=true
CHRONICLE_SOAR_INTEGRATION=true
CHRONICLE_UDM_ANNOTATIONS=true

# PII Scrubbing
SCRUB_PII_FOR_CHRONICLE=false  # Chronicle is internal

# Logging
LOG_LEVEL=info  # debug, info, warning, error
```

### Custom Docker Compose Overrides

Create `docker-compose.override.yml` for custom settings:

```yaml
version: '3.8'

services:
  middleware:
    environment:
      - LOG_LEVEL=debug
    volumes:
      - ./custom_data:/app/custom_data
```

---

## Health Checks and Monitoring

### Service Health

All services have built-in health checks:

```bash
# Check via Makefile
make health

# Or check Docker health
docker-compose ps

# Or query endpoints directly
curl http://localhost:8000/health
curl http://localhost:8001/
docker exec llm-soc-triage-redis redis-cli ping
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f middleware

# Last 100 lines
docker-compose logs --tail=100 middleware

# With timestamps
docker-compose logs -f --timestamps middleware
```

### Resource Usage

```bash
# View container stats
make stats

# Or use Docker directly
docker stats
```

---

## Production-Ready Features

### Security

**Non-root containers**: All services run as non-root users (UID 1000)
```dockerfile
USER appuser  # In Dockerfile
```

**Network isolation**: Services communicate on private bridge network
```yaml
networks:
  soc-triage-network:
    driver: bridge
```

**Health checks**: Automatic health monitoring and restart policies
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
```

**Resource limits** (optional, uncomment in docker-compose.yml):
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```

### Reliability

**Automatic restarts**: Services restart on failure
```yaml
restart: unless-stopped
```

**Data persistence**: Redis data survives container restarts
```yaml
volumes:
  redis_data:
    driver: local
```

**Graceful shutdown**: Proper signal handling
```yaml
stop_grace_period: 30s
```

**Health-aware dependencies**: Services wait for dependencies
```yaml
depends_on:
  redis:
    condition: service_healthy
```

### Observability

**Structured logging**: JSON logs for all services
**Health endpoints**: `/health` on all HTTP services
**Metrics-ready**: Easy to add Prometheus exporters
**Distributed tracing**: Request ID propagation

---

## Troubleshooting

### Issue 1: Containers Won't Start

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs

# Check specific service
docker-compose logs middleware

# Verify .env file
cat .env | grep ANTHROPIC_API_KEY
```

**Common causes**:
- Missing `ANTHROPIC_API_KEY` in `.env`
- Port conflicts (8000, 8001, 6379 already in use)
- Docker daemon not running

### Issue 2: Middleware Unhealthy

```bash
# Check middleware logs
make logs-middleware

# Check environment
docker exec llm-soc-triage-middleware env | grep ANTHROPIC

# Test directly
docker exec llm-soc-triage-middleware curl localhost:8000/health
```

**Common causes**:
- Invalid Anthropic API key
- Network connectivity issues
- Redis not reachable

### Issue 3: Redis Connection Errors

```bash
# Check Redis health
docker exec llm-soc-triage-redis redis-cli ping

# Check Redis logs
make logs-redis

# Verify network
docker exec llm-soc-triage-middleware ping -c 3 redis
```

**Solution**: Redis should be accessible at `redis:6379` within Docker network.

### Issue 4: Port Already in Use

```bash
# Find process using port
lsof -i :8000
lsof -i :8001
lsof -i :6379

# Kill process or change ports in docker-compose.yml
```

### Issue 5: Rebuild Needed

```bash
# Clean rebuild
make rebuild

# Or manually
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

---

## Development Workflow

### Hot Reload (Development Mode)

Edit `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  middleware:
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    volumes:
      - .:/app  # Mount source code
    environment:
      - LOG_LEVEL=debug
```

Then:
```bash
docker-compose up
# Code changes auto-reload
```

### Running Tests

```bash
# Run tests in container
docker exec llm-soc-triage-middleware pytest tests/ -v

# Or with coverage
docker exec llm-soc-triage-middleware pytest tests/ --cov=core --cov-report=html
```

### Debugging

```bash
# Attach to running container
docker attach llm-soc-triage-middleware

# Execute command in container
docker exec llm-soc-triage-middleware python -c "from core.scrubber import get_default_scrubber; print(get_default_scrubber())"

# Interactive Python shell
docker exec -it llm-soc-triage-middleware python
```

---

## Deploying to Production

This Docker Compose setup is production-ready. To deploy:

### Option 1: Docker Swarm

```bash
docker stack deploy -c docker-compose.yml soc-triage
```

### Option 2: Kubernetes

Convert with Kompose:
```bash
kompose convert
kubectl apply -f .
```

### Option 3: AWS ECS/Fargate

1. Push images to ECR
2. Create ECS task definitions
3. Deploy via ECS service

### Option 4: Cloud Run / App Engine

Single-container deployment:
```bash
gcloud run deploy llm-soc-triage --source .
```

---

## Performance Tuning

### Redis Optimization

```yaml
redis:
  command: >
    redis-server
    --appendonly yes
    --maxmemory 512mb
    --maxmemory-policy allkeys-lru
    --tcp-backlog 511
    --timeout 300
```

### Middleware Scaling

```yaml
middleware:
  command: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
  deploy:
    replicas: 2  # Run 2 instances
```

### Resource Limits

```yaml
middleware:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 2G
      reservations:
        cpus: '0.5'
        memory: 512M
```

---

## Next Steps

1. **Run the demo**: `make up && make demo`
2. **Customize**: Edit `.env` for your environment
3. **Test**: Run integration tests with `make test`
4. **Monitor**: Check logs with `make logs`
5. **Deploy**: Push to production when ready

---

## Resources

- Main README: `../README.md`
- Chronicle Integration: `CHRONICLE_INTEGRATION.md`
- Chronicle Demo Guide: `CHRONICLE_DEMO.md`
- Docker Compose Docs: https://docs.docker.com/compose/
- Makefile Reference: Run `make help`

Questions? Open an issue or check the troubleshooting section above.
