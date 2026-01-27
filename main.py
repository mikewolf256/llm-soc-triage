"""
LLM SOC Triage - FastAPI Middleware
The wrapper that orchestrates alert triage using Claude.
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse
import os
from dotenv import load_dotenv
from anthropic import Anthropic
import logging

from core.schema import AlertRequest, TriageResponse
from core.scrubber import scrub_pii
from core.prompt_engine import build_triage_prompt

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="LLM SOC Triage",
    description="AI-powered security alert triage using Claude",
    version="0.1.0"
)

# Initialize Anthropic client
anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "LLM SOC Triage",
        "status": "operational",
        "version": "0.1.0"
    }


@app.post("/triage", response_model=TriageResponse)
async def triage_alert(
    alert: AlertRequest,
    authorization: str = Header(None)
):
    """
    Main triage endpoint
    
    Flow:
    1. Validate incoming alert (Pydantic handles this)
    2. Scrub PII from alert data
    3. Build XML prompt for Claude
    4. Send to Claude for analysis
    5. Parse and return structured response
    """
    try:
        # Optional: Verify API key
        expected_key = os.getenv("API_SECRET_KEY")
        if expected_key and authorization != f"Bearer {expected_key}":
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        logger.info(f"Processing alert: {alert.alert_id}")
        
        # Step 1: Scrub PII
        scrubbed_alert = scrub_pii(alert)
        logger.debug(f"PII scrubbed for alert: {alert.alert_id}")
        
        # Step 2: Build prompt
        prompt = build_triage_prompt(scrubbed_alert)
        logger.debug(f"Prompt built, length: {len(prompt)} chars")
        
        # Step 3: Call Claude
        message = anthropic_client.messages.create(
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
        
        # Step 4: Parse response
        response_text = message.content[0].text
        logger.info(f"Triage complete for alert: {alert.alert_id}")
        
        # TODO: Parse XML response into TriageResponse
        # For now, return a mock response
        return TriageResponse(
            alert_id=alert.alert_id,
            triage_result="NEEDS_INVESTIGATION",
            confidence=0.85,
            reasoning=response_text,
            next_actions=["Review alert details", "Check related logs"],
            iocs=[]
        )
        
    except Exception as e:
        logger.error(f"Error processing alert {alert.alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "anthropic_configured": bool(os.getenv("ANTHROPIC_API_KEY")),
        "model": os.getenv("MODEL_NAME", "claude-3-5-sonnet-20241022")
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
