# Run Demo Instructions

## Quick Start (Run This Now)

Open a terminal and run:

```bash
cd /home/mike/Documents/Cyber/llm-soc-triage
bash start-demo.sh
```

This will:
1. Build Docker images (2-3 minutes)
2. Start all services (middleware, redis, chronicle-mock)
3. Run health checks
4. Display service URLs

## Alternative: Manual Commands

If you prefer to run commands manually:

```bash
cd /home/mike/Documents/Cyber/llm-soc-triage

# Build images
sudo docker-compose build

# Start services
sudo docker-compose up -d

# Check status
sudo docker-compose ps

# View logs
sudo docker-compose logs -f
```

## Running Chronicle Demos

Once services are running, trigger demos:

### Demo 1: High-Confidence IDOR Attack

```bash
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "high_confidence_idor", "middleware_url": "http://middleware:8000"}'
```

### Demo 2: QA Testing False Positive

```bash
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "qa_testing_false_positive", "middleware_url": "http://middleware:8000"}'
```

### Demo 3: Insider Threat

```bash
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "insider_threat_employee", "middleware_url": "http://middleware:8000"}'
```

## View Results

```bash
# Watch middleware processing logs
sudo docker-compose logs -f middleware

# View created Chronicle cases
curl http://localhost:8001/demo/cases | jq

# View UDM annotations
curl http://localhost:8001/demo/annotations | jq

# Test API directly
curl http://localhost:8000/health | jq
```

## Service Access

- **Middleware API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Chronicle Mock**: http://localhost:8001
- **Health Check**: http://localhost:8000/health

## Stopping Services

```bash
# Stop services
sudo docker-compose down

# Stop and remove volumes
sudo docker-compose down -v
```

## Troubleshooting

### Services won't start

```bash
# Check logs
sudo docker-compose logs

# Check specific service
sudo docker-compose logs middleware
```

### Port already in use

```bash
# Check what's using the port
sudo lsof -i :8000
sudo lsof -i :8001
sudo lsof -i :6379
```

### Rebuild everything

```bash
sudo docker-compose down -v
sudo docker-compose build --no-cache
sudo docker-compose up -d
```

## Fix Docker Permissions (Optional)

To avoid needing sudo every time:

```bash
# Add your user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker

# Now you can run without sudo
docker-compose ps
```

## Next Steps

1. Run `bash start-demo.sh` to start the environment
2. Trigger a demo webhook
3. View logs with `sudo docker-compose logs -f`
4. Explore the API at http://localhost:8000/docs
5. Check created cases at http://localhost:8001/demo/cases
