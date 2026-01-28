# Demo Quick Start Guide

## Run Your First Demo (30 seconds)

```bash
cd /home/mike/Documents/Cyber/llm-soc-triage

# Option 1: Quick & reliable test (RECOMMENDED)
bash test-quick.sh

# Option 2: Detailed debug output
bash test-webhook-debug.sh

# Option 3: Comprehensive validation
bash test-all.sh

# Option 4: Test all scenarios
bash run-all-demos.sh
```

**If you get errors:** Make sure Docker services are running first:
```bash
sudo docker-compose up -d
sleep 30  # Wait for startup
bash test-quick.sh
```

## What Was Fixed (2026-01-28)

### Critical Fix: Signature Verification
**Problem:** Webhook signature verification was failing because it reconstructed JSON from the parsed alert, causing formatting mismatches.

**Solution:** Now verifies signature using raw request body BEFORE parsing JSON. This ensures exact byte-for-byte matching.

**Code Change:**
```python
# Before (BROKEN):
async def chronicle_alert_webhook(alert: ChronicleUDMAlert, ...):
    # Alert already parsed, signature check fails
    alert_json = alert.model_dump_json()  # ❌ Different formatting
    handler.verify_signature(alert_json.encode(), signature)

# After (FIXED):
async def chronicle_alert_webhook(request: Request, ...):
    body = await request.body()  # ✓ Raw bytes
    handler.verify_signature(body, signature)  # ✓ Exact match
    alert = ChronicleUDMAlert(**json.loads(body))
```

### Other Fixes
- ✓ API docs URLs corrected (`/docs` and `/redoc`)
- ✓ Enhanced error handling in test scripts
- ✓ All scripts made executable
- ✓ Created comprehensive test suite (`test-all.sh`)

## Test Scripts Overview

| Script | Purpose | Duration | Reliability |
|--------|---------|----------|-------------|
| `test-quick.sh` | **Simple, reliable test** | 10s | ★★★★★ Best |
| `test-webhook-debug.sh` | Detailed webhook test | 15s | ★★★★★ Excellent |
| `test-all.sh` | Comprehensive validation | 30s | ★★★★☆ Good |
| `test-webhook-simple.sh` | Quick webhook test | 10s | ★★★★☆ Good |
| `run-all-demos.sh` | All 4 scenarios | 60s | ★★★★☆ Good |
| `test-demo.sh` | Service health check | 5s | ★★★☆☆ Basic |
| `test-chronicle-webhook.py` | Python webhook test | 15s | ★★★★☆ Good |

**Recommendation:** Start with `test-quick.sh` or `test-webhook-debug.sh` for reliable results.

## Expected Output

When tests pass, you'll see:

```
✓✓ WEBHOOK TEST PASSED!
  Alert ID: chronicle_idor_sequential_enumeration_trigger_2026-01-28T...
  Triage Result: NEEDS_INVESTIGATION
  Confidence: 0.85
  Processing Time: 9086ms

ALL TESTS PASSED ✓
```

## Troubleshooting

### Services Not Running
```bash
sudo docker-compose up -d
sleep 30
bash test-all.sh
```

### API Key Issues
```bash
# Check API key is set
grep ANTHROPIC_API_KEY .env

# If missing, add it
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
sudo docker-compose restart
```

### Check Logs
```bash
# Middleware logs
sudo docker logs llm-soc-triage-middleware | tail -50

# All services
sudo docker-compose logs -f
```

## Demo Scenarios

The `run-all-demos.sh` script tests 4 scenarios:

1. **High-Confidence IDOR** - Sequential enumeration from unknown IP
   - Expected: `CRITICAL_IDOR_ATTACK` (95% confidence)

2. **QA Testing** - Automation from known QA infrastructure
   - Expected: `FALSE_POSITIVE` (95% confidence)

3. **Legitimate Customer** - Customer accessing own resources
   - Expected: `FALSE_POSITIVE` (99% confidence)

4. **Insider Threat** - Employee accessing unauthorized data
   - Expected: `INSIDER_THREAT` (85% confidence)

## Architecture

```
Chronicle YARA-L
    ↓
Webhook (POST /v1/chronicle/webhook)
    ↓
Signature Verification (raw body)
    ↓
Parse JSON → ChronicleUDMAlert
    ↓
PII Scrubbing (Inbound Gate)
    ↓
LLM Triage (Claude 3.5 Haiku)
    ↓
Response → SOAR/Case Creation
```

## Next Steps

1. **Run tests** - Validate everything works
2. **Review logs** - See the processing flow
3. **Modify scenarios** - Edit `tests/fixtures/chronicle_mock_data.py`
4. **Prepare demo** - Practice the 5-minute presentation

## Presentation Tips

**Opening (30s):**
> "I've built a production-ready security triage middleware that integrates with Google Chronicle. Let me show you how it handles a real IDOR attack."

**Demo (2m):**
```bash
bash test-webhook-debug.sh
```
> "Watch the signature verification, PII scrubbing, and LLM analysis. The system correctly identifies this as a potential IDOR attack with 85% confidence."

**Code Review (2m):**
```bash
cat main.py | grep -A 30 "def chronicle_alert_webhook"
```
> "Here's the security architecture - raw body signature verification, then PII scrubbing before the LLM ever sees the data. This is production-ready code."

**Closing (30s):**
> "This demonstrates: security architecture, API integration, LLM orchestration, and Docker deployment. I can deploy this to AWS ECS tomorrow."

---

**Questions?** Check `DEMO_SUCCESS.md` or run `bash test-all.sh` for diagnostics.
