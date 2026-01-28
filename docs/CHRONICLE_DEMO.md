# Chronicle Integration Demo Guide

## Overview

This guide shows how to demo the Chronicle integration using realistic mock data—no Chronicle credentials required. Perfect for:
- Hiring manager presentations
- Development and testing
- Customer demos
- Integration validation

---

## Quick Start (5 Minutes)

### Option 1: Interactive Demo Script

The easiest way to demo the integration:

```bash
# Run interactive demo
python demo_chronicle.py

# Or run specific scenario
python demo_chronicle.py --scenario high_confidence_idor

# Or run all scenarios
python demo_chronicle.py --all

# List available scenarios
python demo_chronicle.py --list
```

**Demo Features**:
- ✓ Realistic Chronicle UDM alerts with PII
- ✓ Step-by-step PII scrubbing visualization
- ✓ Chronicle context enrichment (prevalence, baselines, network intel)
- ✓ LLM analysis with expected verdicts
- ✓ SOAR integration (case creation, UDM annotation)
- ✓ Color-coded output for security boundaries (RED/YELLOW/GREEN)

### Option 2: Mock Chronicle API Server

For testing the actual middleware integration:

```bash
# Terminal 1: Start mock Chronicle API
python tests/fixtures/chronicle_mock_server.py
# Server runs at http://localhost:8001

# Terminal 2: Start middleware (configure to use mock)
export CHRONICLE_REGION=us
export CHRONICLE_CREDENTIALS_FILE=/tmp/mock_creds.json
python main.py
# Middleware runs at http://localhost:8000

# Terminal 3: Trigger webhook with demo scenario
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "high_confidence_idor", "middleware_url": "http://localhost:8000"}'
```

---

## Available Demo Scenarios

### 1. High-Confidence IDOR Attack ⚠️ CRITICAL

**Scenario**: Sequential enumeration of loan IDs from unknown IP with no user baseline.

**Chronicle Context**:
- IOC Prevalence: Never seen before (new attacker)
- User Baseline: No historical data (new account)
- Network Context: Unknown IP, 0 prior connections

**Expected Outcome**:
- Verdict: `CRITICAL_IDOR_ATTACK`
- Confidence: 95%
- Actions: Create Chronicle case, annotate UDM, block session

**Demo Talk Track**:
> "Chronicle detects 4 sequential loan IDs accessed with 403 responses. The middleware queries Chronicle for context—this IP has never connected before, and the user has no baseline. The LLM confirms this is a high-confidence IDOR attack and automatically creates a Chronicle case."

### 2. QA Automation Testing ✓ FALSE POSITIVE

**Scenario**: QA automation bot testing with known test accounts.

**Chronicle Context**:
- User Baseline: Known QA tester with normal patterns
- Network Context: QA infrastructure (known IP range)
- Business Rules: User tagged as `qa_automation`

**Expected Outcome**:
- Verdict: `FALSE_POSITIVE`
- Confidence: 95%
- Actions: Log only, no case creation

**Demo Talk Track**:
> "The middleware recognizes this is a QA automation account based on business context. Chronicle confirms the user's baseline is consistent with testing patterns. The LLM correctly identifies this as a false positive—avoiding alert fatigue for the SOC."

### 3. Legitimate Customer Access ✓ FALSE POSITIVE

**Scenario**: Customer accessing their own loan applications.

**Chronicle Context**:
- Ownership: User accessing own resources (filtered by middleware)
- User Baseline: Normal customer behavior
- Network Context: Internal IP, established session

**Expected Outcome**:
- Verdict: `FALSE_POSITIVE`
- Confidence: 99%
- Actions: Log only

**Demo Talk Track**:
> "This demonstrates the 'ownership-aware' detection. The middleware knows which loans belong to which users. A customer refreshing their own applications doesn't trigger an alert—only unauthorized access does."

### 4. Insider Threat (Employee Snooping) ⚠️ HIGH

**Scenario**: Internal employee accessing customer records outside their assigned portfolio.

**Chronicle Context**:
- User: Internal employee with normal baseline (not typical attacker)
- Network Context: Corporate network (known and trusted)
- Access Pattern: Customer loans outside employee's role

**Expected Outcome**:
- Verdict: `INSIDER_THREAT`
- Confidence: 85%
- Actions: Create HR case, notify security team, audit access
- Compliance: PCI-DSS, SOC 2 CC6.1 flags

**Demo Talk Track**:
> "Chronicle shows this is an employee on the corporate network—normally trusted. But the middleware detects they're accessing customer loans outside their assigned portfolio. This is an insider threat scenario that requires immediate investigation and audit."

---

## Mock Data Details

### Realistic Chronicle UDM Events

The mock data includes production-quality Chronicle UDM events with:

**Metadata**:
```json
{
  "event_type": "HTTP_REQUEST",
  "product_name": "Caribou Web Application Firewall",
  "vendor_name": "Caribou Financial",
  "log_type": "APPLICATION_LOG"
}
```

**Network Context** (Contains PII):
```json
{
  "http": {
    "method": "GET",
    "response_code": 403,
    "user_agent": "Mozilla/5.0...",
    "request_headers": {
      "cookie": "session_id=sess_abc123",
      "x-caribou-id": "sess_abc123",
      "authorization": "Bearer eyJhbGci..."
    }
  }
}
```

**Principal** (User/Source - Contains PII):
```json
{
  "user": {
    "user_id": "user_12849",
    "email_addresses": ["attacker@evil.com"],
    "user_display_name": "attacker"
  },
  "ip": ["192.168.1.100"],
  "hostname": "user_12849-laptop.corp.caribou.com",
  "location": {
    "city": "San Francisco",
    "region_code": "CA"
  }
}
```

**Target** (Resource):
```json
{
  "url": "https://api.caribou.com/api/v1/consumer/loan_applications/4395669",
  "resource": {
    "name": "loan_application_4395669",
    "resource_type": "LOAN_APPLICATION"
  }
}
```

**Security Result**:
```json
{
  "action": "BLOCK",
  "rule_id": "authorization_check_001",
  "rule_name": "Ownership Validation",
  "category": "AUTHORIZATION_FAILURE",
  "severity": "MEDIUM",
  "description": "User attempted to access loan owned by another user"
}
```

### Chronicle API Mock Responses

**IOC Prevalence** (`/v2/ioc/prevalence`):
```json
{
  "indicator": "abc123hash",
  "indicator_type": "hash",
  "affected_asset_count": 3,
  "affected_asset_names": [
    "web-server-01.us-west.caribou.com",
    "api-server-02.us-west.caribou.com",
    "db-server-01.us-east.caribou.com"
  ],
  "first_seen": "2026-01-10T14:32:00Z",
  "last_seen": "2026-01-27T09:15:00Z"
}
```

**User Baseline** (`/v2/users/{user_id}/baseline`):
```json
{
  "user_id": "user_12849",
  "typical_locations": ["San Francisco, CA", "Oakland, CA"],
  "typical_source_ips": ["10.0.15.42", "10.0.15.43"],
  "typical_user_agents": ["Mozilla/5.0 (Macintosh...)"],
  "average_daily_logins": 2.3,
  "baseline_period_days": 30,
  "behavioral_flags": []
}
```

**Network Context** (`/v2/network/{ip_address}`):
```json
{
  "ip_address": "203.0.113.100",
  "first_seen": null,
  "last_seen": null,
  "connection_count": 0,
  "connected_assets": [],
  "reputation_score": null,
  "threat_intel": {
    "is_malicious": null,
    "categories": ["proxy", "vpn"],
    "sources": ["VirusTotal", "AbuseIPDB"]
  }
}
```

---

## PII Scrubbing Demonstration

The demo visually shows PII scrubbing at security boundaries:

### Before Scrubbing (Raw Chronicle UDM):
```json
{
  "principal": {
    "user": {
      "email_addresses": ["attacker@evil.com"]
    },
    "ip": ["192.168.1.100"],
    "hostname": "attacker-laptop.corp.caribou.com"
  }
}
```

### After Scrubbing (LLM-Safe):
```json
{
  "principal": {
    "user": {
      "email_addresses": ["[EMAIL_REDACTED]"]
    },
    "ip": ["[IP_REDACTED]"],
    "hostname": "[HOSTNAME_REDACTED]"
  }
}
```

**Correlation Tokens Preserved**:
- `user_id`: Preserved for LLM correlation
- `session_id`: Preserved for session tracking
- Resource IDs: Preserved for pattern detection

---

## Mock Server API Reference

### Demo Helper Endpoints

**GET** `/` - Health check and endpoint listing

**GET** `/demo/scenarios` - List all demo scenarios
```bash
curl http://localhost:8001/demo/scenarios
```

**POST** `/demo/trigger-webhook` - Trigger middleware webhook
```bash
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -H "Content-Type: application/json" \
  -d '{"scenario": "high_confidence_idor", "middleware_url": "http://localhost:8000"}'
```

**GET** `/demo/cases` - View created Chronicle cases
```bash
curl http://localhost:8001/demo/cases
```

**GET** `/demo/annotations` - View UDM annotations
```bash
curl http://localhost:8001/demo/annotations
```

### Chronicle API Endpoints (Mocked)

**GET** `/v2/ioc/prevalence` - IOC prevalence query
```bash
curl "http://localhost:8001/v2/ioc/prevalence?indicator=abc123hash&indicator_type=hash"
```

**GET** `/v2/users/{user_id}/baseline` - User baseline query
```bash
curl http://localhost:8001/v2/users/user_12849/baseline
```

**GET** `/v2/network/{ip_address}` - Network context query
```bash
curl http://localhost:8001/v2/network/203.0.113.100
```

**POST** `/v2/udm/search` - UDM search
```bash
curl -X POST http://localhost:8001/v2/udm/search \
  -H "Content-Type: application/json" \
  -d '{"query": "event_type = HTTP_REQUEST", "max_results": 10}'
```

**POST** `/v2/cases` - Create Chronicle case
```bash
curl -X POST http://localhost:8001/v2/cases \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Case", "severity": "HIGH"}'
```

**POST** `/v2/udm/annotate` - Annotate UDM event
```bash
curl -X POST http://localhost:8001/v2/udm/annotate \
  -H "Content-Type: application/json" \
  -d '{"event_id": "udm_evt_123", "annotation_text": "AI triage result"}'
```

---

## Hiring Manager Demo Script

**Duration**: 10 minutes  
**Goal**: Show Chronicle integration, PII scrubbing, and context-aware detection

### Setup (1 minute)
```bash
# Terminal window with large font
python demo_chronicle.py
```

### Demo Flow (8 minutes)

**Scene 1: High-Confidence Attack (3 min)**
1. Select Scenario 1: High-Confidence IDOR
2. Show Chronicle raw UDM with PII highlighted
3. Demonstrate PII scrubbing (before/after)
4. Show Chronicle context enrichment (prevalence, baseline, network)
5. Show LLM verdict: CRITICAL (95% confidence)
6. Show SOAR actions: Case created, UDM annotated

**Talk Track**:
> "Chronicle detects the pattern and forwards raw logs to our middleware. Notice the PII—emails, IPs, hostnames. Our middleware scrubs this before LLM analysis—GDPR compliance. Then we query Chronicle for context: Is this hash common? Is this user's behavior normal? Has this IP connected before? Chronicle says 'no, no, no'—new attacker. The LLM confirms it's a high-confidence IDOR attack and automatically creates a Chronicle case."

**Scene 2: False Positive (QA Testing) (2 min)**
1. Select Scenario 2: QA Testing
2. Show business context: User tagged as `qa_automation`
3. Show Chronicle baseline: Known tester patterns
4. Show LLM verdict: FALSE_POSITIVE (95% confidence)
5. Show action: Log only, no case

**Talk Track**:
> "Now watch what happens with QA testing. Same pattern—multiple 403s. But our business context knows this is a QA bot. Chronicle confirms the baseline matches testing patterns. The LLM correctly identifies this as a false positive. No alert fatigue for the SOC."

**Scene 3: Insider Threat (3 min)**
1. Select Scenario 4: Insider Threat
2. Show employee credentials (corporate network)
3. Show Chronicle: Normal user baseline (not typical attacker)
4. Show access pattern: Loans outside assigned portfolio
5. Show LLM verdict: INSIDER_THREAT (85% confidence)
6. Show compliance flags: PCI-DSS, SOC 2

**Talk Track**:
> "Here's where it gets interesting. This is an employee on our corporate network—Chronicle shows normal login patterns. But they're accessing customer loans they shouldn't have access to. The middleware detects this as an insider threat. It's not just external attacks—we catch internal data snooping too. Compliance flags are raised for PCI-DSS audit."

### Q&A (1 minute)

**Expected Questions**:
1. "How do you prevent PII leaks to the LLM?"
   - **Answer**: Three-gate architecture. Chronicle data scrubbed at inbound gate (RED), context queries scrubbed at execution gate (YELLOW), outbound always scrubbed for UDM annotations (GREEN, compliance).

2. "What if Chronicle is slow?"
   - **Answer**: Async queries with <2s timeout. Graceful degradation—if Chronicle is down, we fall back to local business rules. Performance: <2s for enrichment, 95%+ uptime.

3. "Can this work with other SIEMs?"
   - **Answer**: Yes. Chronicle is one integration point. We have generic webhook support for Splunk, Sentinel, QRadar. See `docs/SIEM_DETECTION_RULES.md`.

---

## Testing the Integration

### Unit Tests (Mock Data)
```bash
# Run Chronicle integration tests
pytest tests/test_chronicle_integration.py -v

# Test specific functionality
pytest tests/test_chronicle_integration.py::TestUDMPIIScrubbing -v
```

### Integration Test (Mock Server + Middleware)
```bash
# Terminal 1: Start mock Chronicle
python tests/fixtures/chronicle_mock_server.py

# Terminal 2: Start middleware
python main.py

# Terminal 3: Run integration test
curl -X POST http://localhost:8001/demo/trigger-webhook \
  -d '{"scenario": "high_confidence_idor"}' \
  -H "Content-Type: application/json"

# Check results
curl http://localhost:8001/demo/cases
curl http://localhost:8001/demo/annotations
```

---

## Extending Mock Data

### Add Custom Scenario

Edit `tests/fixtures/chronicle_mock_data.py`:

```python
def get_demo_scenario_custom() -> Dict[str, Any]:
    """Your custom scenario."""
    alert = get_mock_idor_alert(num_attempts=10, sequential=True)
    
    # Customize alert
    alert["risk_score"] = 95
    alert["severity"] = "CRITICAL"
    
    # Add custom context
    context = {
        "prevalence": {...},
        "user_baseline": {...},
    }
    
    return {
        "scenario": "custom_scenario",
        "description": "Your scenario description",
        "alert": alert,
        "chronicle_context": context,
        "expected_verdict": "YOUR_VERDICT",
        "expected_confidence": 0.90,
    }
```

### Customize UDM Events

```python
# Custom UDM event with your data
udm_event = get_mock_udm_event(
    loan_id=1234567,
    user_id="user_custom",
    user_email="test@example.com",
    source_ip="10.0.0.1",
    session_id="sess_custom",
    response_code=403,
)
```

---

## Troubleshooting

**Issue**: Mock server won't start (port 8001 in use)
```bash
# Find process using port
lsof -i :8001

# Kill process or change port in chronicle_mock_server.py
```

**Issue**: Demo script can't find mock data
```bash
# Ensure you're in project root
cd /path/to/llm-soc-triage
python demo_chronicle.py
```

**Issue**: Colors not rendering in terminal
```bash
# Use a terminal that supports ANSI colors
# Or disable colors in demo_chronicle.py
```

---

## Production vs. Demo

| Feature | Demo (Mock) | Production (Real Chronicle) |
|---------|-------------|----------------------------|
| **Authentication** | None required | Service account credentials |
| **API Endpoints** | Localhost:8001 | `https://{region}.backstory.chronicle.security` |
| **Webhook Signature** | `test_secret_key` | Real HMAC secret |
| **UDM Data** | Synthetic/realistic | Real production logs |
| **Latency** | <10ms (in-memory) | <2s (API queries) |
| **Cost** | Free | Chronicle API usage fees |
| **Use Case** | Demos, testing, development | Production SOC operations |

---

## Resources

- Mock Data: `tests/fixtures/chronicle_mock_data.py`
- Mock Server: `tests/fixtures/chronicle_mock_server.py`
- Demo Script: `demo_chronicle.py`
- Integration Docs: `docs/CHRONICLE_INTEGRATION.md`
- YARA-L Rules: `docs/chronicle_yara_rules/idor_detection.yaral`
- Tests: `tests/test_chronicle_integration.py`

---

## Next Steps

1. **Run the Demo**: `python demo_chronicle.py`
2. **Customize Scenarios**: Edit `chronicle_mock_data.py`
3. **Test Integration**: Start mock server + middleware
4. **Deploy to Production**: See `docs/CHRONICLE_INTEGRATION.md`

Questions? Check the main integration guide or open an issue.
