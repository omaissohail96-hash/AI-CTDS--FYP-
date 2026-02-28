"""
Cyber Security Dashboard - FastAPI Backend
Provides API endpoints for threat detection using trained ML models.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn

# Import detectors
from detectors.url_feature_extractor import extract_url_features
from detectors.email_detector import predict_email_attack
from detectors.network_detectors import predict_network_attacks
from detectors.web_detector import predict_web_attack

# Import Orchestration Layer
from src.agent.orchestrator import SecurityAgent

# Initialize FastAPI app
app = FastAPI(
    title="CyberGuard AI - Threat Detection SaaS",
    description="Enterprise-grade AI Security Agent for multi-vector threat detection",
    version="2.0.0"
)

# Initialize Security Agent
security_agent = SecurityAgent()

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== REQUEST MODELS ====================

class AgentAnalyzeRequest(BaseModel):
    type: str = "auto"
    data: Any
    metadata: Optional[Dict[str, Any]] = None

class URLScanRequest(BaseModel):
    url: str

class EmailScanRequest(BaseModel):
    subject: str
    body: str

class NetworkScanRequest(BaseModel):
    flow_features: Dict[str, Any]

class WebAttackRequest(BaseModel):
    url: str

# ==================== RESPONSE MODELS ====================

class ScanResponse(BaseModel):
    success: bool
    attack_type: str
    confidence: float
    severity: str
    details: Optional[Dict[str, Any]] = None

# ==================== API ENDPOINTS (V2 - AGENT) ====================

@app.post("/api/v1/agent/analyze")
async def agent_analyze(request: AgentAnalyzeRequest):
    """
    Unified AI Agent endpoint. 
    Orchestrates multiple models and provides a consolidated risk score.
    """
    try:
        tenant_id = request.metadata.get("workspace_id", "default") if request.metadata else "default"
        # In a real SaaS, we would validate the tenant's API key/quota here
        
        agent = SecurityAgent(tenant_id=tenant_id)
        result = await agent.analyze_payload({"type": request.type, "data": request.data})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==================== LEGACY ENDPOINTS (V1 - COMPATIBILITY) ====================

@app.get("/")
async def root():
    return {
        "message": "CyberGuard AI Gateway",
        "version": "2.0.0",
        "agent_endpoint": "/api/v1/agent/analyze",
        "legacy_endpoints": ["/api/scan/url", "/api/scan/email", "/api/scan/network", "/api/scan/web"]
    }

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "message": "Agent Orchestrator Online"}


@app.post("/api/scan/url", response_model=ScanResponse)
async def scan_url(request: URLScanRequest):
    try:
        agent = SecurityAgent()
        analysis = await agent.analyze_payload({"type": "url", "data": request.url})
        result = analysis["vector_details"][0]
        
        return ScanResponse(
            success=True,
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            severity=result["severity"],
            details=analysis["agent_verdict"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/email", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest):
    try:
        agent = SecurityAgent()
        analysis = await agent.analyze_payload({"type": "email", "data": {"subject": request.subject, "body": request.body}})
        result = analysis["vector_details"][0]
        
        return ScanResponse(
            success=True,
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            severity=result["severity"],
            details=analysis["agent_verdict"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/network", response_model=ScanResponse)
async def scan_network(request: NetworkScanRequest):
    try:
        agent = SecurityAgent()
        analysis = await agent.analyze_payload({"type": "network", "data": request.flow_features})
        result = analysis["vector_details"][0]
        
        return ScanResponse(
            success=True,
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            severity=result["severity"],
            details=analysis["agent_verdict"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/web", response_model=ScanResponse)
async def scan_web_attack(request: WebAttackRequest):
    try:
        agent = SecurityAgent()
        analysis = await agent.analyze_payload({"type": "url", "data": request.url})
        result = analysis["vector_details"][0]
        
        return ScanResponse(
            success=True,
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            severity=result["severity"],
            details=analysis["agent_verdict"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== RUN SERVER ====================

if __name__ == "__main__":
    print("🛡️ CyberGuard AI Orchestrator Started...")
    print("📍 API Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)

