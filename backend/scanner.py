"""
VulnHunter AI — Core scanner engine.
Fetches a public GitHub repo, analyzes code with Claude for OWASP Top 10,
and returns structured findings with severity ratings and fix suggestions.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import structlog
from anthropic import AsyncAnthropic

log = structlog.get_logger()

GITHUB_API = "https://api.github.com"
MAX_FILE_BYTES = 80_000   # skip files larger than this
MAX_FILES      = 40       # cap total files per scan

# File extensions worth scanning
SCANNABLE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".cs", ".cpp", ".c", ".rs",
    ".yaml", ".yml", ".json", ".env", ".toml", ".ini", ".cfg",
    ".sh", ".bash", ".zsh",
    "Dockerfile", ".dockerfile",
}

SKIP_PATTERNS = re.compile(
    r"(node_modules|\.git|dist/|build/|__pycache__|vendor/|\.min\.|"
    r"package-lock\.json|yarn\.lock|poetry\.lock|Gemfile\.lock|go\.sum)",
    re.IGNORECASE,
)

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    owasp_id:    str
    owasp_name:  str
    severity:    Severity
    title:       str
    description: str
    file_path:   str
    line_number: Optional[int]
    vulnerable_snippet: str
    recommended_fix: str
    cwe_id:      Optional[str] = None


@dataclass
class ScanResult:
    repo_url:      str
    repo_name:     str
    files_scanned: int
    findings:      list[Finding] = field(default_factory=list)
    scan_summary:  str = ""
    risk_score:    int = 0          # 0–100
    error:         Optional[str]  = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def risk_label(self) -> str:
        if self.error is not None:
            return "INCOMPLETE"
        if self.risk_score >= 75: return "CRITICAL"
        if self.risk_score >= 50: return "HIGH"
        if self.risk_score >= 25: return "MEDIUM"
        if self.risk_score > 0:  return "LOW"
        return "CLEAN"

    @property
    def owasp_breakdown(self) -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for f in self.findings:
            breakdown[f.owasp_id] = breakdown.get(f.owasp_id, 0) + 1
        return breakdown


class GitHubFetcher:
    """Fetches file tree and contents from a public GitHub repository."""

    def __init__(self, token: Optional[str] = None):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(headers=headers, timeout=30.0)

    async def close(self):
        await self._client.aclose()

    @staticmethod
    def parse_repo(url: str) -> tuple[str, str]:
        """Extract owner/repo from GitHub URL."""
        url = url.rstrip("/")
        # Handle: https://github.com/owner/repo  or  github.com/owner/repo  or  owner/repo
        m = re.search(r"(?:github\.com/)?([^/]+)/([^/]+?)(?:\.git)?$", url)
        if not m:
            raise ValueError(f"Cannot parse GitHub URL: {url}")
        return m.group(1), m.group(2)

    async def get_default_branch(self, owner: str, repo: str) -> str:
        r = await self._client.get(f"{GITHUB_API}/repos/{owner}/{repo}")
        r.raise_for_status()
        return r.json().get("default_branch", "main")

    async def list_files(self, owner: str, repo: str, branch: str) -> list[str]:
        """Return a flat list of file paths using the git trees API (recursive)."""
        r = await self._client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        r.raise_for_status()
        data = r.json()
        paths = [
            item["path"] for item in data.get("tree", [])
            if item["type"] == "blob"
            and not SKIP_PATTERNS.search(item["path"])
            and (
                any(item["path"].endswith(ext) for ext in SCANNABLE_EXTS)
                or item["path"] in ("Dockerfile",)
            )
            and item.get("size", 0) <= MAX_FILE_BYTES
        ]
        return paths[:MAX_FILES]

    async def get_file(self, owner: str, repo: str, path: str) -> str:
        r = await self._client.get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}")
        r.raise_for_status()
        data = r.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content", "")

    async def fetch_repo_files(self, owner: str, repo: str) -> dict[str, str]:
        branch = await self.get_default_branch(owner, repo)
        paths  = await self.list_files(owner, repo, branch)
        log.info("fetching_files", count=len(paths), repo=f"{owner}/{repo}")

        async def fetch_one(path: str) -> tuple[str, str]:
            try:
                content = await self.get_file(owner, repo, path)
                return path, content
            except Exception as e:
                log.warning("file_fetch_failed", path=path, error=str(e))
                return path, ""

        results = await asyncio.gather(*[fetch_one(p) for p in paths])
        return {p: c for p, c in results if c}


ANALYSIS_SYSTEM_PROMPT = """You are an elite application security engineer specializing in OWASP Top 10 vulnerability analysis.
Your job is to analyze source code for security vulnerabilities and produce structured JSON findings.

For each vulnerability you find, output a JSON object with these exact fields:
{
  "owasp_id": "A01" (through A10),
  "owasp_name": "the full category name",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "title": "short title of the vulnerability",
  "description": "2-3 sentences explaining what the vulnerability is and why it's dangerous",
  "line_number": <integer or null>,
  "vulnerable_snippet": "the exact vulnerable line(s) of code, max 3 lines",
  "recommended_fix": "the fixed version of the vulnerable code or fix instruction, max 4 lines",
  "cwe_id": "CWE-XXX" or null
}

Severity guidelines:
- CRITICAL: Remote code execution, authentication bypass, SQL injection with data exfil
- HIGH: IDOR, XSS with session theft potential, hardcoded secrets/API keys, command injection
- MEDIUM: Missing rate limiting, weak crypto, verbose error messages, CSRF
- LOW: Missing security headers, informational leakage, minor misconfiguration
- INFO: Best practice improvements

Be thorough but precise. Only report real vulnerabilities, not theoretical ones.
Return ONLY a JSON array of findings (empty array [] if none found). No prose, no markdown."""


class AnalysisError(RuntimeError):
    """A file did not receive a complete, valid analysis."""


def _parse_findings(raw: str, path: str) -> list[Finding]:
    """Validate the entire reply before accepting any of its findings."""
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    items = json.loads(raw)
    if not isinstance(items, list):
        raise ValueError("Expected an array of findings")

    findings = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each finding must be an object")
        for key in ("owasp_id", "owasp_name", "severity", "title", "description",
                    "vulnerable_snippet", "recommended_fix"):
            if not isinstance(item.get(key), str):
                raise ValueError(f"Invalid finding field: {key}")
        if item["owasp_id"] not in OWASP_CATEGORIES:
            raise ValueError("Unknown OWASP category")
        line = item.get("line_number")
        if line is not None and (type(line) is not int or line < 1):
            raise ValueError("Invalid line number")
        cwe = item.get("cwe_id")
        if cwe is not None and (not isinstance(cwe, str) or not cwe.strip()):
            raise ValueError("Invalid CWE identifier")
        findings.append(Finding(
            owasp_id=item["owasp_id"], owasp_name=item["owasp_name"],
            severity=Severity(item["severity"]), title=item["title"],
            description=item["description"], file_path=path, line_number=line,
            vulnerable_snippet=item["vulnerable_snippet"],
            recommended_fix=item["recommended_fix"], cwe_id=cwe,
        ))
    return findings


class VulnScanner:
    """Orchestrates repo fetching + AI analysis."""

    def __init__(self, anthropic_api_key: str, github_token: Optional[str] = None):
        self._ai = AsyncAnthropic(api_key=anthropic_api_key)
        self._gh = GitHubFetcher(token=github_token)

    async def close(self):
        await self._gh.close()

    async def _analyze_file(self, path: str, content: str) -> list[Finding]:
        """Send a single file to Claude for OWASP analysis."""
        if not content.strip():
            return []

        prompt = f"""Analyze this file for OWASP Top 10 security vulnerabilities.

File: {path}
---
{content[:15000]}
---

Return a JSON array of findings (empty [] if none). Each finding must match the schema in your system prompt."""

        try:
            msg = await self._ai.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=2048,
                system=ANALYSIS_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            if msg.stop_reason not in ("end_turn", "stop_sequence"):
                raise ValueError("Analysis response did not finish")
            if not msg.content or any(block.type != "text" for block in msg.content):
                raise ValueError("Expected text analysis output")
            raw = "\n".join(block.text for block in msg.content).strip()
            return _parse_findings(raw, path)

        except Exception as e:
            log.error("ai_analysis_failed", path=path, error=str(e))
            raise AnalysisError(f"Analysis failed for {path}") from e

    async def _generate_summary(self, repo_name: str, findings: list[Finding]) -> str:
        """Generate an executive summary of the scan."""
        if not findings:
            return f"No findings were returned for the analyzed files in **{repo_name}**. This automated review is not proof that the repository is secure."

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity.value] += 1

        owasp_hits = {}
        for f in findings:
            owasp_hits[f.owasp_id] = owasp_hits.get(f.owasp_id, 0) + 1

        top_owasp = sorted(owasp_hits.items(), key=lambda x: x[1], reverse=True)[:3]

        prompt = f"""Write a 3-sentence executive summary for a security scan of the repository '{repo_name}'.

Findings: {counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low
Top vulnerability categories: {', '.join(f"{oid} ({OWASP_CATEGORIES.get(oid,'?')}): {cnt}" for oid, cnt in top_owasp)}

Be direct and professional. Mention the most urgent issues. End with a clear recommendation.
Return only the summary text, no headers."""

        try:
            msg = await self._ai.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text.strip()
        except Exception:
            return f"Scan complete. Found {len(findings)} issue(s): {counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low."

    @staticmethod
    def _compute_risk_score(findings: list[Finding]) -> int:
        """Compute a 0–100 risk score from findings."""
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        raw = sum(weights.get(f.severity.value, 0) for f in findings)
        return min(100, raw)

    async def scan(self, repo_url: str) -> ScanResult:
        """Full scan pipeline: fetch → analyze → summarize."""
        try:
            owner, repo = GitHubFetcher.parse_repo(repo_url)
        except ValueError as e:
            return ScanResult(repo_url=repo_url, repo_name=repo_url, files_scanned=0, error=str(e))

        repo_name = f"{owner}/{repo}"
        log.info("scan_started", repo=repo_name)

        try:
            files = await self._gh.fetch_repo_files(owner, repo)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ScanResult(repo_url=repo_url, repo_name=repo_name, files_scanned=0,
                                  error="Repository not found. Make sure the repo is public.")
            return ScanResult(repo_url=repo_url, repo_name=repo_name, files_scanned=0,
                              error=f"GitHub API error: {e.response.status_code}")
        except Exception as e:
            return ScanResult(repo_url=repo_url, repo_name=repo_name, files_scanned=0, error=str(e))

        if not files:
            return ScanResult(repo_url=repo_url, repo_name=repo_name, files_scanned=0,
                              error="No scannable files found in this repository.")

        # Analyze files concurrently (batch of 8 to respect rate limits)
        all_findings: list[Finding] = []
        failed_files = 0
        batch_size = 8
        file_items = list(files.items())

        for i in range(0, len(file_items), batch_size):
            batch = file_items[i:i + batch_size]
            batch_results = await asyncio.gather(*[
                self._analyze_file(path, content)
                for path, content in batch
            ], return_exceptions=True)
            for file_findings in batch_results:
                if isinstance(file_findings, asyncio.CancelledError):
                    raise file_findings
                if isinstance(file_findings, Exception):
                    failed_files += 1
                else:
                    all_findings.extend(file_findings)

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.severity.value, 5))

        error = None
        if failed_files:
            error = (f"Analysis incomplete: {failed_files} of {len(files)} files could not "
                     "be analyzed. Any findings are partial. Please retry the scan.")
            summary = error
        else:
            summary = await self._generate_summary(repo_name, all_findings)
        risk_score = self._compute_risk_score(all_findings)

        log.info("scan_incomplete" if error else "scan_complete", repo=repo_name,
                 findings=len(all_findings), risk_score=risk_score, failed_files=failed_files)

        return ScanResult(
            repo_url      = repo_url,
            repo_name     = repo_name,
            files_scanned = len(files) - failed_files,
            findings      = all_findings,
            scan_summary  = summary,
            risk_score    = risk_score,
            error         = error,
        )

