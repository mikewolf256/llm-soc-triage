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

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse
import os
from dotenv import load_dotenv
from anthropic import Anthropic
import logging
from datetime import datetime

from core.schema import AlertRequest, TriageResponse
from core.scrubber import scrub_pii
from core.prompt_engine import build_triage_prompt, parse_triage_response

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
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Initialize Anthropic client (lazy loaded for better error handling)
anthropic_client = None

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
        
        # Step 2: RAG - Retrieve Historical Context
        # Interview Point: "This is where institutional knowledge gets leveraged.
        # If we've seen similar alerts before, we surface how they were resolved."
        historical_context = retrieve_historical_context(alert)
        logger.debug(f"[RAG_RETRIEVED] alert_id={alert.alert_id} similar_case={historical_context.get('similar_case_id')} score={historical_context.get('similarity_score')}")
        
        # Step 3: Build Secure Prompt with XML Delimiters
        # Interview Point: "The XML tags prevent prompt injection. If an attacker
        # puts 'Ignore previous instructions' in a log file, the LLM won't follow it
        # because it's clearly marked as untrusted data."
        prompt = build_triage_prompt(scrubbed_alert)
        logger.debug(f"[PROMPT_BUILT] alert_id={alert.alert_id} length={len(prompt)}")
        
        # Step 4: Structured LLM Call
        client = get_llm_client()
        message = client.messages.create(
            model=os.getenv("MODEL_NAME", "claude-3-5-sonnet-20241022"),
            max_tokens=int(os.getenv("MAX_TOKENS", "4096")),
            temperature=float(os.getenv("TEMPERATURE", "0.0")),
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        # Step 5: Parse XML Response into Structured Output
        response_text = message.content[0].text
        parsed_response = parse_triage_response(response_text)
        
        # Step 6: Build Response with Metadata
        triage_response = TriageResponse(
            alert_id=alert.alert_id,
            triage_result=parsed_response.get("triage_result", "NEEDS_INVESTIGATION"),
            confidence=parsed_response.get("confidence", 0.0),
            reasoning=parsed_response.get("reasoning", response_text),
            next_actions=parsed_response.get("next_actions", []),
            iocs=parsed_response.get("iocs", []),
            model_used=os.getenv("MODEL_NAME", "claude-3-5-sonnet-20241022")
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
            "model": os.getenv("MODEL_NAME", "claude-3-5-sonnet-20241022"),
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
