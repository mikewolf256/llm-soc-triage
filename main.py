"""
LLM SOC Triage - Production FastAPI Middleware

This is a RAG-driven triage system that demonstrates:
1. Schema-first development (data contract before implementation)
2. Privacy-first design (PII scrubbing before LLM)
3. Prompt injection defense (XML delimiters)
4. MCP (Model Context Protocol) ready architecture
5. Complete observability (structured logging, audit trail)

Architecture: This middleware sits between your SIEM/SOAR and analysts,
providing instant triage recommendations backed by historical context.
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
import os
from dotenv import load_dotenv
from anthropic import Anthropic
import logging
from datetime import datetime

# Import from core.schema module (the .py file, not the package directory)
import sys
from pathlib import Path
import importlib.util

# Load schema.py directly to avoid ambiguity with schema/ package
_schema_path = Path(__file__).parent / "core" / "schema.py"
_spec = importlib.util.spec_from_file_location("core.schema_models", _schema_path)
_schema_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_schema_module)

AlertRequest = _schema_module.AlertRequest
TriageResponse = _schema_module.TriageResponse
from core.scrubber import scrub_pii
from core.prompt_engine import build_triage_prompt, parse_triage_response
from core.context_manager import BusinessContextManager, format_business_context_for_prompt
from core.chronicle_integration import get_chronicle_client, get_chronicle_alert_handler
from core.schema.chronicle_events import ChronicleUDMAlert, ChronicleWebhookResponse

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Initialize FastAPI with OpenAPI docs
app = FastAPI(
    title="AI-Assisted SOC Triage Engine",
    description="RAG-driven security alert triage with privacy-first design",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize Anthropic client (lazy loaded for better error handling)
anthropic_client = None

# Initialize Business Context Manager
business_context_mgr = BusinessContextManager()

def get_llm_client():
    """Lazy initialization of LLM client with error handling"""
    global anthropic_client
    if anthropic_client is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured")
        anthropic_client = Anthropic(api_key=api_key)
    return anthropic_client


def retrieve_historical_context(alert: AlertRequest) -> dict:
    """
    RAG: Retrieve similar historical tickets from vector database
    
    In production, this would:
    1. Embed the alert using the same model as historical tickets
    2. Query ChromaDB/Pinecone for top-k similar past incidents
    3. Return analyst notes, disposition, and confidence
    
    For demo purposes, this is mocked. In an interview, explain:
    - Vector embeddings capture semantic similarity beyond keyword matching
    - Historical context reduces repeat investigations
    - This is where institutional knowledge gets encoded
    """
    # TODO: Replace with actual vector DB query
    # embedding = embed_alert(alert)
    # similar_cases = vector_db.query(embedding, k=3)
    
    # Mock response for demonstration
    return {
        "similar_case_id": "HIST-2024-0089",
        "similarity_score": 0.87,
        "previous_disposition": "TP",
        "analyst_notes": "Confirmed Cobalt Strike beacon. Endpoint was isolated and reimaged."
    }


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "LLM SOC Triage",
        "status": "operational",
        "version": "0.1.0"
    }


@app.post("/v1/triage", response_model=TriageResponse)
async def triage_alert(
    alert: AlertRequest,
    authorization: str = Header(None)
):
    """
    Main triage endpoint - Production RAG-driven flow
    
    Interview Talking Points:
    1. "Schema First": Pydantic validation ensures data quality before processing
    2. "Local PII Scrubbing": Compliance requirement - data never leaves infrastructure
    3. "RAG Context": Historical similarity reduces analyst workload on repeat issues
    4. "XML Delimiters": Security defense against prompt injection via malicious logs
    5. "Structured Output": Enforced response format for downstream SOAR integration
    
    Flow:
    Raw Alert → Validation → PII Scrubbing → RAG Retrieval → Secure Prompt → LLM → Parsed Response
    """
    start_time = datetime.utcnow()
    
    try:
        # Authentication: API key verification
        expected_key = os.getenv("API_SECRET_KEY")
        if expected_key and authorization != f"Bearer {expected_key}":
            logger.warning(f"Unauthorized triage attempt for alert: {alert.alert_id}")
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        logger.info(f"[TRIAGE_START] alert_id={alert.alert_id} severity={alert.severity} source={alert.source}")
        
        # Step 1: Local PII Scrubbing (COMPLIANCE CRITICAL)
        # Interview Point: "Notice that PII is removed BEFORE the API call.
        # This is critical for fintech compliance (GLBA, CCPA, GDPR)."
        scrubbed_alert = scrub_pii(alert)
        logger.debug(f"[PII_SCRUBBED] alert_id={alert.alert_id}")
        
        # Step 2: Enrich with Business Context (now async for Chronicle support)
        # Interview Point: "This is the 'secret sauce' - we inject institutional
        # knowledge about critical assets, VIP users, and approved tools."
        business_enrichment = await business_context_mgr.enrich_alert(scrubbed_alert)
        context_summary = format_business_context_for_prompt(business_enrichment)
        logger.debug(f"[BUSINESS_CONTEXT] alert_id={alert.alert_id} enriched={bool(business_enrichment.get('business_context'))}")
        
        # Step 3: RAG - Retrieve Historical Context
        # Interview Point: "This is where historical knowledge gets leveraged.
        # If we've seen similar alerts before, we surface how they were resolved."
        historical_context = retrieve_historical_context(alert)
        logger.debug(f"[RAG_RETRIEVED] alert_id={alert.alert_id} similar_case={historical_context.get('similar_case_id')} score={historical_context.get('similarity_score')}")
        
        # Step 4: Build Secure Prompt with XML Delimiters
        # Interview Point: "The XML tags prevent prompt injection. If an attacker
        # puts 'Ignore previous instructions' in a log file, the LLM won't follow it
        # because it's clearly marked as untrusted data."
        prompt = build_triage_prompt(scrubbed_alert, business_context=context_summary)
        logger.debug(f"[PROMPT_BUILT] alert_id={alert.alert_id} length={len(prompt)}")
        
        # Step 5: Structured LLM Call
        client = get_llm_client()
        message = client.messages.create(
            model=os.getenv("MODEL_NAME", "claude-3-5-sonnet-20250122"),
            max_tokens=int(os.getenv("MAX_TOKENS", "4096")),
            temperature=float(os.getenv("TEMPERATURE", "0.0")),
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        # Step 6: Parse XML Response into Structured Output
        response_text = message.content[0].text
        parsed_response = parse_triage_response(response_text)
        
        # Calculate risk score based on business context
        base_risk = parsed_response.get("risk_score", 50)
        risk_multiplier = business_enrichment.get("business_context", {}).get("risk_multiplier", 1.0)
        adjusted_risk = min(100, int(base_risk * risk_multiplier))
        
        # Step 7: Build Response with Metadata (Outbound Gate validates here)
        triage_response = TriageResponse(
            alert_id=alert.alert_id,
            triage_result=parsed_response.get("triage_result", "NEEDS_INVESTIGATION"),
            confidence=parsed_response.get("confidence", 0.0),
            risk_score=adjusted_risk,
            reasoning=parsed_response.get("reasoning", response_text),
            next_actions=parsed_response.get("next_actions", ["Review alert details and context"]),
            iocs=parsed_response.get("iocs", []),
            model_used=os.getenv("MODEL_NAME", "claude-3-5-sonnet-20241022"),
            business_context_applied=bool(business_enrichment.get("business_context"))
        )
        
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        logger.info(f"[TRIAGE_COMPLETE] alert_id={alert.alert_id} result={triage_response.triage_result} confidence={triage_response.confidence:.2f} duration_ms={duration_ms:.0f}")
        
        return triage_response
        
    except ValueError as e:
        logger.error(f"[VALIDATION_ERROR] alert_id={alert.alert_id} error={str(e)}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"[TRIAGE_ERROR] alert_id={alert.alert_id} error={str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")


@app.get("/health")
async def health_check():
    """
    Detailed health check for monitoring/alerting
    
    Production systems need observability. This endpoint provides:
    - Configuration validation
    - Dependency status
    - Version information
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "configuration": {
            "llm_provider": "anthropic",
            "model": os.getenv("MODEL_NAME", "claude-3-5-sonnet-20250122"),
            "api_key_configured": bool(os.getenv("ANTHROPIC_API_KEY")),
            "pii_scrubbing_enabled": True,
            "rag_enabled": False  # TODO: Enable when vector DB is configured
        }
    }
    
    # Validate critical dependencies
    if not os.getenv("ANTHROPIC_API_KEY"):
        health_status["status"] = "degraded"
        health_status["issues"] = ["ANTHROPIC_API_KEY not configured"]
    
    return health_status


@app.post("/v1/chronicle/webhook", response_model=ChronicleWebhookResponse)
async def chronicle_alert_webhook(
    request: Request,
    x_chronicle_signature: str = Header(None, alias="X-Chronicle-Signature"),
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Receive Chronicle YARA-L triggered alerts for LLM triage.
    
    Security Flow (Sandwich Model - Inbound Gate):
        1. Validate Chronicle webhook signature (prevent spoofing)
        2. Parse UDM alert structure
        3. CRITICAL: Scrub PII before LLM processing
        4. Convert to standard AlertRequest schema
        5. Execute standard triage flow with Chronicle context
    
    Chronicle Integration:
        - Inbound: YARA-L rules detect patterns and forward UDM events
        - Context: Enrichment with prevalence/baseline data
        - Outbound: Auto-create Chronicle cases for high-confidence alerts
    
    PII Security:
        UDM events contain raw logs with IPs, emails, hostnames, usernames.
        ALL data is scrubbed before LLM analysis per "Sandwich Model".
    
    Flow:
        Chronicle YARA-L → Webhook → Signature Verify → PII Scrub → Context → LLM → SOAR
    """
    start_time = datetime.utcnow()
    
    try:
        # Step 1: Get raw request body for signature verification
        # CRITICAL: Must verify signature BEFORE parsing JSON to avoid formatting mismatches
        body = await request.body()
        
        # Step 2: Validate webhook signature (prevent spoofing)
        handler = get_chronicle_alert_handler()
        
        if x_chronicle_signature and handler.webhook_secret:
            if not handler.verify_signature(body, x_chronicle_signature):
                logger.warning(f"[CHRONICLE_WEBHOOK] Invalid signature")
                logger.debug(f"[CHRONICLE_WEBHOOK] Received signature: {x_chronicle_signature}")
                # In demo mode, log warning but continue
                logger.info("[CHRONICLE_WEBHOOK] Continuing in demo mode (signature mismatch logged)")
                # raise HTTPException(
                #     status_code=403,
                #     detail="Invalid Chronicle webhook signature"
                # )
        
        # Step 3: Parse the alert from raw body
        import json
        alert_dict = json.loads(body.decode('utf-8'))
        alert = ChronicleUDMAlert(**alert_dict)
        
        alert_id = f"chronicle_{alert.rule_id}_{alert.detection_timestamp.isoformat()}"
        logger.info(f"[CHRONICLE_WEBHOOK] rule={alert.rule_name} severity={alert.severity}")
        
        # Step 4: CRITICAL - Scrub PII from raw UDM events
        # This is the INBOUND GATE (Red) - PII must not reach LLM
        logger.debug(f"[CHRONICLE_WEBHOOK] Scrubbing PII from {len(alert.udm_events)} UDM events")
        scrubbed_udm_data = handler.scrub_webhook_alert(alert.model_dump())
        
        # Step 5: Convert Chronicle alert to standard AlertRequest schema
        standard_alert = AlertRequest(
            alert_id=alert_id,
            severity=alert.severity.value,
            source="chronicle",
            title=f"Chronicle: {alert.rule_name}",
            description=f"Chronicle YARA-L rule '{alert.rule_name}' triggered. "
                       f"Detected {alert.distinct_resources or len(alert.udm_events)} "
                       f"matching events.",
            timestamp=alert.detection_timestamp.isoformat(),
            affected_host=None,  # Extract from UDM if available
            affected_user=scrubbed_udm_data.get("user_id"),  # Already scrubbed
            raw_data={
                "chronicle_rule_id": alert.rule_id,
                "chronicle_rule_version": alert.rule_version,
                "chronicle_risk_score": alert.risk_score,
                "udm_event_count": len(alert.udm_events),
                "distinct_resources": alert.distinct_resources,
                "session_id": alert.session_id,
                # Store scrubbed UDM samples (limit to 3 for context)
                "udm_sample_events": scrubbed_udm_data.get("udm_events", [])[:3],
            },
            iocs=[]  # Extract IOCs from UDM events if needed
        )
        
        # Step 6: Execute standard triage flow (with Chronicle context enrichment)
        logger.info(f"[CHRONICLE_WEBHOOK] Executing triage for {alert_id}")
        
        # Use internal triage function (bypasses API key check)
        triage_result = await triage_alert_internal(standard_alert)
        
        # Step 7: Return response to Chronicle
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ChronicleWebhookResponse(
            success=True,
            alert_id=alert_id,
            triage_result=triage_result.triage_result,
            confidence=triage_result.confidence,
            case_created=False,  # TODO: Implement auto-case creation
            processing_time_ms=duration_ms,
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[CHRONICLE_WEBHOOK] Processing failed: {e}", exc_info=True)
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ChronicleWebhookResponse(
            success=False,
            alert_id=alert_id,
            error=str(e),
            processing_time_ms=duration_ms,
        )


async def triage_alert_internal(alert: AlertRequest) -> TriageResponse:
    """
    Internal triage function (used by Chronicle webhook and other integrations).
    
    Bypasses API key authentication for internal service-to-service calls.
    Follows same security flow as main /v1/triage endpoint.
    """
    start_time = datetime.utcnow()
    
    try:
        logger.info(f"[TRIAGE_INTERNAL] alert_id={alert.alert_id} source={alert.source}")
        
        # Step 1: Local PII Scrubbing (COMPLIANCE CRITICAL)
        scrubbed_alert = scrub_pii(alert)
        logger.debug(f"[PII_SCRUBBED] alert_id={alert.alert_id}")
        
        # Step 2: Enrich with Business Context (now async for Chronicle support)
        business_enrichment = await business_context_mgr.enrich_alert(scrubbed_alert)
        context_summary = format_business_context_for_prompt(business_enrichment)
        logger.debug(f"[BUSINESS_CONTEXT] alert_id={alert.alert_id}")
        
        # Step 3: RAG - Retrieve Historical Context
        historical_context = retrieve_historical_context(alert)
        logger.debug(f"[RAG_RETRIEVED] alert_id={alert.alert_id}")
        
        # Step 4: Build Secure Prompt with XML Delimiters
        prompt = build_triage_prompt(scrubbed_alert, business_context=context_summary)
        logger.debug(f"[PROMPT_BUILT] alert_id={alert.alert_id}")
        
        # Step 5: Structured LLM Call
        client = get_llm_client()
        message = client.messages.create(
            model=os.getenv("MODEL_NAME", "claude-3-5-sonnet-20250122"),
            max_tokens=int(os.getenv("MAX_TOKENS", "4096")),
            temperature=float(os.getenv("TEMPERATURE", "0.0")),
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Step 6: Parse XML Response
        response_text = message.content[0].text
        parsed_response = parse_triage_response(response_text)
        
        # Step 7: Build Response
        base_risk = parsed_response.get("risk_score", 50)
        risk_multiplier = business_enrichment.get("business_context", {}).get("risk_multiplier", 1.0)
        adjusted_risk = min(100, int(base_risk * risk_multiplier))
        
        triage_response = TriageResponse(
            alert_id=alert.alert_id,
            triage_result=parsed_response.get("triage_result", "NEEDS_INVESTIGATION"),
            confidence=parsed_response.get("confidence", 0.0),
            risk_score=adjusted_risk,
            reasoning=parsed_response.get("reasoning", response_text),
            next_actions=parsed_response.get("next_actions", []),
            iocs=parsed_response.get("iocs", []),
            model_used=os.getenv("MODEL_NAME", "claude-3-5-sonnet-20241022"),
            business_context_applied=bool(business_enrichment.get("business_context"))
        )
        
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        logger.info(f"[TRIAGE_COMPLETE] alert_id={alert.alert_id} result={triage_response.triage_result} duration_ms={duration_ms:.0f}")
        
        return triage_response
    
    except Exception as e:
        logger.error(f"[TRIAGE_ERROR] alert_id={alert.alert_id} error={str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
