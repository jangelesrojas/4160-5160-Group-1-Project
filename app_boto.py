# This is the main FastAPI app for the M2/M3 demo.
# It exposes three endpoints: /scan, /prioritize, /fix
# - /scan: collects findings (either from AWS via boto3 or from mock data)
# - /prioritize: gives each finding a simple priority score
# - /fix: asks the LLM (or uses a safe fallback) to suggest a tiny IaC patch + explanation

import os
import json
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Body
from pydantic import BaseModel, Field
from datetime import datetime
from openai import OpenAI  # OpenAI client for LLM calls

# Toggle for using real AWS collectors (boto3) vs mock data.
# If you set USE_BOTO=1 in your shell, /scan will call run_collectors() from collectors.py.
USE_BOTO = os.getenv("USE_BOTO", "0") == "1"
if USE_BOTO:
    from collectors import run_collectors

# If OPENAI_API_KEY is NOT set, client will be None and we will use safe fallbacks in /fix.
client = OpenAI() if os.getenv("OPENAI_API_KEY") else None

# Basic FastAPI app metadata (shows up in Swagger UI)
app = FastAPI(title="M2 Demo: Cloud Misconfig Detection (boto-enabled)", version="0.3.0")

# ---------------------------
# Pydantic data models (these control Swagger schemas and request/response validation)
# ---------------------------

class Finding(BaseModel):
    # A single misconfiguration or risk item discovered by /scan
    resource: str
    service: str
    issue: str
    severity: str
    details: Dict[str, Any] = {}

class ScanResponse(BaseModel):
    # What /scan returns: an id, an account label, and a list of findings
    scan_id: str
    account: str
    findings: List[Finding]

class PrioritizeRequest(BaseModel):
    # What /prioritize expects: a list of findings and optional weights for the simple score
    findings: List[Finding]
    weights: Optional[Dict[str, float]] = Field(
        default_factory=lambda: {"exploitability": 0.6, "blast_radius": 0.4}
    )

class PrioritizedFinding(Finding):
    # Same as Finding but adds a priority_score integer
    priority_score: int

class PrioritizeResponse(BaseModel):
    # What /prioritize returns: a new scan id and a sorted list of prioritized findings
    scan_id: str
    prioritized_findings: List[PrioritizedFinding]

class FixRequest(BaseModel):
    # What /fix expects: the prioritized findings array
    findings: List[PrioritizedFinding]

class FixSuggestion(BaseModel):
    # One LLM (or fallback) suggestion for a single finding
    resource: str
    service: str
    suggested_fix: str
    iac_patch: Dict[str, Any]
    explanation: str

class FixResponse(BaseModel):
    # What /fix returns: a list of suggestions (one per input finding)
    suggestions: List[FixSuggestion]

# ---------------------------
# Mock findings (used when USE_BOTO != 1)
# This keeps the demo runnable even without AWS creds or seeded resources.
# ---------------------------
def _mock_findings():
    return [
        {"resource": "s3://student-project-bucket", "service": "s3",
         "issue": "Bucket allows public read", "severity": "high",
         "details": {"acl": "public-read"}},
        {"resource": "iam:role/StudentAdmin", "service": "iam",
         "issue": "Overly broad Admin policy attached", "severity": "medium",
         "details": {"policy": "AdministratorAccess"}},
        {"resource": "sg-0123456789", "service": "ec2",
         "issue": "Security group allows 0.0.0.0/0 on port 22", "severity": "high",
         "details": {"port": 22}}
    ]

# ---------------------------
# Simple safety guard for LLM patches
# We quickly scan the returned JSON to reject anything obviously unsafe.
# If it fails, we swap to a safe fallback template.
# ---------------------------
def _guard_patch(service: str, patch: Dict[str, Any]) -> bool:
    text = json.dumps(patch).lower()
    if service == "s3":
        # Never accept public-read suggestions from the LLM
        if "public-read" in text:
            return False
        return True
    if service == "iam":
        # Never accept AdministratorAccess from the LLM
        if "administratoraccess" in text:
            return False
        return True
    if service == "ec2":
        # Do not allow 0.0.0.0/0 on port 22
        if "0.0.0.0/0" in text and "22" in text:
            return False
        return True
    # For services we did not explicitly check, allow it (human-in-the-loop will review)
    return True

# ---------------------------
# Safe fallback patches (used when there is no API key, JSON parse error, or guard failure)
# These are small and reasonable fixes that make the demo reliable.
# ---------------------------
def _safe_fallback(service: str) -> Dict[str, Any]:
    if service == "s3":
        return {
            "terraform": {
                "aws_s3_bucket_public_access_block": {
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True
                },
                "aws_s3_bucket_acl": {"acl": "private"}
            },
            "explanation": "Make the bucket private and block public access."
        }
    if service == "iam":
        return {
            "terraform": {
                "aws_iam_policy_document": {
                    "statement": [{
                        "effect": "Allow",
                        "actions": ["s3:GetObject"],
                        "resources": ["arn:aws:s3:::student-project-bucket/*"]
                    }]
                }
            },
            "explanation": "Replace full admin with least privilege read only."
        }
    if service == "ec2":
        return {
            "terraform": {
                "aws_security_group_rule": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["203.0.113.0/24"]
                }
            },
            "explanation": "Lock down SSH to a restricted CIDR."
        }
    # Generic fallback if we do not recognize the service
    return {
        "terraform": {"note": "generic fallback template"},
        "explanation": "Suggesting a minimal safe change for this resource."
    }

# ---------------------------
# LLM helper: asks the model for a tiny Terraform-style patch + a short explanation.
# If OPENAI_API_KEY is missing or anything goes wrong, we return the safe fallback above.
# ---------------------------
def _llm_patch_json(finding: Dict[str, Any]) -> Dict[str, Any]:
    # Basic fields pulled from the finding (kept small on purpose)
    service = finding.get("service", "")
    resource = finding.get("resource", "")
    issue = finding.get("issue", "")
    details = finding.get("details", {})

    # Short instructions the model will follow (kept super simple for predictable output)
    instructions = [
        "Return ONLY a JSON object with keys: terraform, explanation.",
        "Keep the terraform block very small and focused on the fix.",
        "No prose outside JSON. No markdown."
    ]
    if service == "s3":
        instructions.append("Make the bucket private. Block all public access. Set ACL to private.")
    elif service == "iam":
        instructions.append("Remove AdministratorAccess. Grant only least privilege needed such as s3:GetObject on a specific bucket.")
    elif service == "ec2":
        instructions.append("Replace 0.0.0.0/0 on port 22 with a restricted CIDR like 203.0.113.0/24.")

    # If no API key, we skip the model call and just return the safe fallback so demos never break
    if client is None:
        return _safe_fallback(service)

    try:
        # Ask the model in JSON mode so it returns valid JSON we can parse
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,  # low temp for stable outputs
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You output only valid JSON that matches the requested keys."},
                {"role": "user", "content": json.dumps({
                    "resource": resource,
                    "service": service,
                    "issue": issue,
                    "details": details,
                    "instructions": instructions
                })}
            ],
        )
        raw = resp.choices[0].message.content
        patch = json.loads(raw)  # parse JSON result from the model
    except Exception:
        # If anything fails (network, JSON parse, etc.), return the safe fallback
        return _safe_fallback(service)

    # Run guard checks to avoid unsafe suggestions; fallback if it fails
    if not _guard_patch(service, patch):
        return _safe_fallback(service)
    return patch

# ---------------------------
# /scan: returns findings either from real AWS (when USE_BOTO=1) or from mock data (default)
# ---------------------------
@app.post("/scan", response_model=ScanResponse)
def scan(account_id: str = Body(..., embed=True)):
    scan_id = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    if USE_BOTO:
        # Real mode: call collectors.py to gather actual AWS findings
        findings = [Finding(**f) for f in run_collectors()]
    else:
        # Mock mode: return hard-coded examples so the demo always works
        findings = [Finding(**f) for f in _mock_findings()]
    return ScanResponse(scan_id=scan_id, account=account_id, findings=findings)

# ---------------------------
# /prioritize: gives each finding a basic score using severity + a simple blast radius proxy
# ---------------------------
@app.post("/prioritize", response_model=PrioritizeResponse)
def prioritize(req: PrioritizeRequest):
    sev_map = {"low": 20, "medium": 60, "high": 90}
    br_map  = {"s3": 90, "iam": 75, "ec2": 80}
    sev_w, br_w = req.weights.get("exploitability", 0.6), req.weights.get("blast_radius", 0.4)

    scored: List[PrioritizedFinding] = []
    for f in req.findings:
        sev = sev_map.get(f.severity.lower(), 40)
        br  = br_map.get(f.service.lower(), 50)
        score = int(sev * sev_w + br * br_w)  # weighted sum → simple int
        scored.append(PrioritizedFinding(**f.dict(), priority_score=score))

    # Sort highest score first so the most important items show up on top
    scored.sort(key=lambda x: x.priority_score, reverse=True)
    return PrioritizeResponse(scan_id=datetime.utcnow().strftime("%Y%m%d%H%M%S"), prioritized_findings=scored)

# ---------------------------
# /fix: for each prioritized finding, ask the LLM for a tiny IaC patch + short explanation.
# If the model is unavailable or returns something unsafe, we use a safe fallback patch.
# ---------------------------
@app.post("/fix", response_model=FixResponse)
def fix(req: FixRequest):
    suggestions: List[FixSuggestion] = []

    for pf in req.findings:
        # Convert Pydantic model to a plain dict for the helper
        find_obj = {
            "resource": pf.resource,
            "service": pf.service,
            "issue": pf.issue,
            "severity": pf.severity,
            "details": pf.details
        }

        # Get the LLM (or fallback) suggestion
        patch = _llm_patch_json(find_obj)
        explanation = patch.get("explanation", "Short explanation unavailable.")

        # The API contract expects a dict for iac_patch. If anything looks odd, keep it predictable.
        iac_patch = patch if isinstance(patch, dict) else {
            "terraform": {"note": "unexpected format"},
            "explanation": explanation
        }

        # Build the final suggestion item
        suggestions.append(FixSuggestion(
            resource=pf.resource,
            service=pf.service,
            suggested_fix=pf.issue,
            iac_patch= iac_patch,
            explanation= explanation
        ))

    return FixResponse(suggestions=suggestions)



