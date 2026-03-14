"""
VulnHunter AI — FastAPI backend.
Exposes scan endpoints consumed by the React frontend.
"""

from __future__ import annotations

import os
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional

import structlog
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl, field_validator

from scanner import VulnScanner, ScanResult, Severity

load_dotenv()
log = structlog.get_logger()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN")          # optional — raises rate limit 60→5000/hr

# ── In-memory scan cache (resets on restart — fine for demo) ──────────────────
_scan_cache: dict[str, dict] = {}
_scan_locks: dict[str, asyncio.Lock] = {}

app = FastAPI(
    title="VulnHunter AI",
    description="AI-powered OWASP security scanner for public GitHub repositories",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("repo_url is required")
        # Allow owner/repo shorthand
        if "/" in v and not v.startswith("http"):
            v = f"https://github.com/{v}"
        if "github.com" not in v:
            raise ValueError("Only public GitHub repositories are supported")
        return v


class FindingOut(BaseModel):
    owasp_id:           str
    owasp_name:         str
    severity:           str
    title:              str
    description:        str
    file_path:          str
    line_number:        Optional[int]
    vulnerable_snippet: str
    recommended_fix:    str
    cwe_id:             Optional[str]


class ScanResultOut(BaseModel):
    scan_id:       str
    repo_url:      str
    repo_name:     str
    files_scanned: int
    findings:      list[FindingOut]
    scan_summary:  str
    risk_score:    int
    risk_label:    str
    critical_count: int
    high_count:    int
    medium_count:  int
    low_count:     int
    owasp_breakdown: dict[str, int]
    scanned_at:    str
    error:         Optional[str]


class ScanStatusOut(BaseModel):
    scan_id: str
    status:  str          # "pending" | "running" | "complete" | "error"
    repo_url: str
    progress: Optional[str] = None


def result_to_out(scan_id: str, result: ScanResult) -> ScanResultOut:
    return ScanResultOut(
        scan_id        = scan_id,
        repo_url       = result.repo_url,
        repo_name      = result.repo_name,
        files_scanned  = result.files_scanned,
        findings       = [FindingOut(**{
            "owasp_id":           f.owasp_id,
            "owasp_name":         f.owasp_name,
            "severity":           f.severity.value,
            "title":              f.title,
            "description":        f.description,
            "file_path":          f.file_path,
            "line_number":        f.line_number,
            "vulnerable_snippet": f.vulnerable_snippet,
            "recommended_fix":    f.recommended_fix,
            "cwe_id":             f.cwe_id,
        }) for f in result.findings],
        scan_summary   = result.scan_summary,
        risk_score     = result.risk_score,
        risk_label     = result.risk_label,
        critical_count = result.critical_count,
        high_count     = result.high_count,
        medium_count   = result.medium_count,
        low_count      = result.low_count,
        owasp_breakdown= result.owasp_breakdown,
        scanned_at     = datetime.now(timezone.utc).isoformat(),
        error          = result.error,
    )


# ── Background scan task ──────────────────────────────────────────────────────

async def _run_scan(scan_id: str, repo_url: str):
    _scan_cache[scan_id]["status"] = "running"
    scanner = VulnScanner(
        anthropic_api_key=ANTHROPIC_API_KEY,
        github_token=GITHUB_TOKEN,
    )
    try:
        result = await scanner.scan(repo_url)
        _scan_cache[scan_id]["status"] = "complete" if not result.error else "error"
        _scan_cache[scan_id]["result"] = result_to_out(scan_id, result)
    except Exception as e:
        log.error("scan_failed", scan_id=scan_id, error=str(e))
        _scan_cache[scan_id]["status"] = "error"
        _scan_cache[scan_id]["result"] = ScanResultOut(
            scan_id=scan_id, repo_url=repo_url, repo_name=repo_url,
            files_scanned=0, findings=[], scan_summary="",
            risk_score=0, risk_label="CLEAN",
            critical_count=0, high_count=0, medium_count=0, low_count=0,
            owasp_breakdown={}, scanned_at=datetime.now(timezone.utc).isoformat(),
            error=str(e),
        )
    finally:
        await scanner.close()


# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "api_key_set": bool(ANTHROPIC_API_KEY)}


@app.post("/api/scan", response_model=ScanStatusOut, status_code=202)
async def start_scan(req: ScanRequest):
    """Start an async scan. Returns a scan_id to poll for results."""
    if not ANTHROPIC_API_KEY:
        raise HTTPException(503, "ANTHROPIC_API_KEY not configured")

    scan_id = str(uuid.uuid4())[:8]
    _scan_cache[scan_id] = {"status": "pending", "repo_url": req.repo_url, "result": None}

    asyncio.create_task(_run_scan(scan_id, req.repo_url))

    return ScanStatusOut(
        scan_id  = scan_id,
        status   = "pending",
        repo_url = req.repo_url,
        progress = "Scan queued — fetching repository files…",
    )


@app.get("/api/scan/{scan_id}/status", response_model=ScanStatusOut)
async def get_scan_status(scan_id: str):
    if scan_id not in _scan_cache:
        raise HTTPException(404, "Scan not found")
    entry = _scan_cache[scan_id]
    messages = {
        "pending": "Fetching repository files…",
        "running": "Analyzing code for OWASP vulnerabilities…",
        "complete": "Scan complete",
        "error": "Scan failed",
    }
    return ScanStatusOut(
        scan_id  = scan_id,
        status   = entry["status"],
        repo_url = entry["repo_url"],
        progress = messages.get(entry["status"], ""),
    )


@app.get("/api/scan/{scan_id}/result", response_model=ScanResultOut)
async def get_scan_result(scan_id: str):
    if scan_id not in _scan_cache:
        raise HTTPException(404, "Scan not found")
    entry = _scan_cache[scan_id]
    if entry["status"] not in ("complete", "error"):
        raise HTTPException(202, "Scan still in progress")
    return entry["result"]


@app.get("/api/demos")
async def list_demos():
    """Return a list of interesting public repos for demo purposes."""
    return {
        "demos": [
            {"label": "DVWA (Damn Vulnerable Web App)", "url": "https://github.com/digininja/DVWA"},
            {"label": "WebGoat (OWASP)",               "url": "https://github.com/WebGoat/WebGoat"},
            {"label": "NodeGoat (OWASP)",              "url": "https://github.com/OWASP/NodeGoat"},
            {"label": "Juice Shop (OWASP)",            "url": "https://github.com/juice-shop/juice-shop"},
            {"label": "VAmPI (vulnerable REST API)",   "url": "https://github.com/erev0s/VAmPI"},
        ]
    }


# ── Static files (serve frontend) ────────────────────────────────────────────
import os as _os
_static_dir = _os.path.join(_os.path.dirname(__file__), "..", "frontend")
if _os.path.isdir(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="frontend")
