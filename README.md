# LLM SOC Triage

**The 3AM Alert Whisperer**: Turn noisy security alerts into actionable intelligence using Claude.

## The Problem

SOC analysts are drowning in alerts. 95% are noise. The 5% that matter are buried in jargon, scattered across tools, and require tribal knowledge to triage properly.

## The Solution

A FastAPI middleware that:
1. **Normalizes** alerts from any source into a unified schema
2. **Scrubs** PII/secrets before they touch the LLM
3. **Enriches** with context using Claude's reasoning
4. **Triages** with confidence scores and next actions

## Why This Matters

- **Speed**: Triage in seconds, not minutes
- **Consistency**: Every alert gets the same expert-level analysis
- **Security**: PII stays local, only redacted data goes to the LLM
- **Transparency**: XML-structured prompts show exactly what the LLM sees

## Quick Start

```bash
# Setup
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your API keys

# Run
uvicorn main:app --reload

# Test
curl -X POST http://localhost:8000/triage \
  -H "Content-Type: application/json" \
  -d @examples/sample_alert.json
```

## Architecture

```
Raw Alert → Normalize → Scrub PII → Prompt Engine → Claude → Structured Response
```

### Key Components

- **main.py**: FastAPI wrapper with `/triage` endpoint
- **core/schema.py**: Pydantic models for validation
- **core/scrubber.py**: PII redaction using Presidio
- **core/prompt_engine.py**: XML prompt construction
- **data/normalized_schema.json**: Master alert schema

## Example Request

```json
{
  "alert_id": "ALT-2024-001",
  "severity": "HIGH",
  "source": "crowdstrike",
  "title": "Suspicious PowerShell Execution",
  "description": "User john.doe@acme.com executed base64-encoded PowerShell",
  "timestamp": "2024-01-27T03:45:00Z",
  "raw_data": { ... }
}
```

## Example Response

```json
{
  "alert_id": "ALT-2024-001",
  "triage_result": "CRITICAL",
  "confidence": 0.92,
  "reasoning": "Base64 PowerShell with external C2 indicators...",
  "next_actions": [
    "Isolate endpoint immediately",
    "Dump memory for malware analysis",
    "Check for lateral movement"
  ],
  "iocs": ["185.220.101.42", "update-checker.xyz"]
}
```

## Security Features

- ✅ PII redaction before LLM processing
- ✅ API key management via environment variables
- ✅ Request validation with Pydantic
- ✅ Rate limiting (TODO)
- ✅ Audit logging (TODO)

## Testing

```bash
pytest tests/ -v --cov=core
```

## Roadmap

- [ ] Multi-LLM support (OpenAI, local models)
- [ ] Alert history for pattern detection
- [ ] Integration playbooks (Slack, PagerDuty)
- [ ] Fine-tuned models for specific alert types

## License

MIT

## Contributing

PRs welcome! Focus areas:
- Additional alert source schemas
- PII detection improvements
- Prompt engineering optimizations
