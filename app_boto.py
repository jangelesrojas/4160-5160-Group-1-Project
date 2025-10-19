import os
import json
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Body
from pydantic import BaseModel, Field
from datetime import datetime
from openai import OpenAI

# USE_BOTO flag lets you switch between mock mode (demo data) and real AWS scans
USE_BOTO = os.getenv("USE_BOTO", "0") == "1"
if USE_BOTO:
    from collectors import run_collectors  # Import real scan logic

client = OpenAI() if os.getenv("OPENAI_API_KEY") else None  # For /fix endpoint (AI copilot)

app = FastAPI(title="M2 Demo: Cloud Misconfig Detection", version="1.0")

# Data models describe the shape of each API’s request and response
class Finding(BaseModel):
    resource: str
    service: str
    issue: str
    severity: str
    details: Dict[str, Any] = {}

class ScanResponse(BaseModel):
    scan_id: str
    account: str
    findings: List[Finding]

class PrioritizeRequest(BaseModel):
    findings: List[Finding]
    weights: Optional[Dict[str, float]] = Field(default_factory=lambda: {"exploitability": 0.6, "blast_radius": 0.4})

class PrioritizedFinding(Finding):
    priority_score: int

class PrioritizeResponse(BaseModel):
    scan_id: str
    prioritized_findings: List[PrioritizedFinding]

class FixRequest(BaseModel):
    findings: List[PrioritizedFinding]

class FixSuggestion(BaseModel):
    resource: str
    service: str
    suggested_fix: str
    iac_patch: Dict[str, Any]
    explanation: str

class FixResponse(BaseModel):
    suggestions: List[FixSuggestion]

# This is just mock data for demo mode (no AWS needed)
def _mock_findings():
    return [
        {"resource": "s3://student-project-bucket", "service": "s3", "issue": "Bucket allows public read", "severity": "high"},
        {"resource": "iam:role/StudentAdmin", "service": "iam", "issue": "Overly broad Admin policy attached", "severity": "medium"},
        {"resource": "sg-0123456789", "service": "ec2", "issue": "Security group allows 0.0.0.0/0 on port 22", "severity": "high"}
    ]

# /scan endpoint collects cloud data or loads demo data
@app.post("/scan", response_model=ScanResponse)
def scan(account_id: str = Body(..., embed=True)):
    scan_id = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    if USE_BOTO:
        # Real scan (calls collectors.py)
        findings = [Finding(**f) for f in run_collectors()]
    else:
        # Demo mode
        findings = [Finding(**f) for f in _mock_findings()]

    return ScanResponse(scan_id=scan_id, account=account_id, findings=findings)


# /prioritize sorts findings by risk and blast radius
@app.post("/prioritize", response_model=PrioritizeResponse)
def prioritize(req: PrioritizeRequest):
    sev_map = {"low": 20, "medium": 60, "high": 90}
    br_map = {"s3": 90, "iam": 75, "ec2": 80}
    sev_w, br_w = req.weights.get("exploitability", 0.6), req.weights.get("blast_radius", 0.4)

    scored = []
    for f in req.findings:
        sev = sev_map.get(f.severity.lower(), 40)
        br = br_map.get(f.service.lower(), 50)
        score = int(sev * sev_w + br * br_w)
        scored.append(PrioritizedFinding(**f.dict(), priority_score=score))

    scored.sort(key=lambda x: x.priority_score, reverse=True)
    return PrioritizeResponse(scan_id=datetime.utcnow().strftime("%Y%m%d%H%M%S"), prioritized_findings=scored)


# Helper to talk to OpenAI
def _llm(prompt: str) -> str:
    if client is None:
        return '{"terraform": {"note": "offline demo mode"}, "explanation": "Set ACL to private and block public access."}'
    res = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Return a compact JSON object with keys terraform and explanation."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )
    return res.choices[0].message.content.strip()


# /fix endpoint calls OpenAI to generate patch suggestions for each issue
@app.post("/fix", response_model=FixResponse)
def fix(req: FixRequest):
    out = []
    for pf in req.findings:
        # Generate a custom prompt depending on what service the issue came from
        if pf.service == "s3":
            prompt = f"Terraform JSON to block public access for {pf.resource}. Include explanation."
        elif pf.service == "iam":
            prompt = f"Terraform JSON to remove admin privileges from {pf.resource}. Include explanation."
        elif pf.service == "ec2":
            prompt = f"Terraform JSON to restrict port 22 for {pf.resource} to internal IPs. Include explanation."
        else:
            prompt = f"Basic Terraform fix for {pf.resource}. Include explanation."

        text = _llm(prompt)

        # Try to parse the LLM output as JSON (so it fits into the IaC patch section)
        patch, explanation = {"terraform": "/* patch */"}, "Default explanation."
        try:
            parsed = json.loads(text)
            patch = parsed
            explanation = parsed.get("explanation", explanation)
        except Exception:
            pass

        out.append(FixSuggestion(
            resource=pf.resource,
            service=pf.service,
            suggested_fix=pf.issue,
            iac_patch=patch,
            explanation=explanation
        ))

    return FixResponse(suggestions=out)

