"""
Agentic Protocol and MCP Security Analyzer (OWASP LLM Top 10).
Detects prompt injection sinks, excessive agency in tool manifests,
unconstrained MCP tool definitions, and credential leakage in agent workflows.
"""

from __future__ import annotations

import re

from backend.scanner import Finding, OWASP_LLM_CATEGORIES, Severity

# Regex patterns for high-risk agentic tool declarations lacking confirmation or isolation
HIGH_RISK_TOOL_NAME = re.compile(
    r"['\"]?(?:tool_name|name|command)['\"]?\s*[:=]\s*['\"](bash|shell|exec|eval|system_cmd|run_terminal|sql_exec|delete_tenant|revoke_all)['\"]",
    re.IGNORECASE,
)

# Unchecked dynamic interpolation into system prompt / instructions
PROMPT_INJECTION_SINK = re.compile(
    r"(?:system_prompt|instructions|system_message)\s*[:=]\s*(?:f['\"].*?\{.*?(?:user_input|prompt|query|message|body|request).*?\}.*?['\"]|.*?\.format\(.*?(?:user_input|prompt|query|message|body|request).*?\))",
    re.IGNORECASE,
)

# Sensitive bearer tokens or auth headers forwarded directly to LLM context
AUTH_HEADER_FORWARD = re.compile(
    r"(?:messages|prompt|context)\.append\s*\(\s*\{.*?['\"](?:authorization|bearer|x-api-key|token)['\"]\s*:\s*(?:req|request|headers|auth).*?\}\s*\)",
    re.IGNORECASE,
)

# MCP tool declaration with empty or permissive input schema
MCP_OPEN_SCHEMA = re.compile(
    r"['\"]inputSchema['\"]\s*:\s*\{\s*['\"]type['\"]\s*:\s*['\"]object['\"]\s*\}",
    re.IGNORECASE,
)


def _find_line_number(content: str, match_pos: int) -> int:
    return content[:match_pos].count("\n") + 1


def _extract_snippet(content: str, line_no: int, num_lines: int = 3) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1)
    end = min(len(lines), start + num_lines)
    return "\n".join(lines[start:end])


def analyze_agentic_code(path: str, content: str) -> list[Finding]:
    """Analyze a single file for agentic protocol vulnerabilities and LLM security anti-patterns."""
    findings: list[Finding] = []
    if not content.strip():
        return findings

    # Check 1: LLM01 - Prompt Injection Sinks in System Instructions
    for m in PROMPT_INJECTION_SINK.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(Finding(
            owasp_id="LLM01",
            owasp_name=OWASP_LLM_CATEGORIES["LLM01"],
            severity=Severity.HIGH,
            title="Direct Prompt Injection Sink in System Prompt",
            description=(
                "Untrusted user input is directly concatenated or formatted into the agent's "
                "system prompt/instruction stream without structural delimiter guards or parameterization."
            ),
            file_path=path,
            line_number=line,
            vulnerable_snippet=snippet,
            recommended_fix=(
                "Isolate untrusted user input within dedicated user message roles or wrap in "
                "verifiable XML/fenced delimiter tags with prompt-isolation policies."
            ),
            cwe_id="CWE-77",
        ))

    # Check 2: LLM06 - Excessive Agency in High-Risk Agent/MCP Tools
    for m in HIGH_RISK_TOOL_NAME.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        tool_name = m.group(1)
        findings.append(Finding(
            owasp_id="LLM06",
            owasp_name=OWASP_LLM_CATEGORIES["LLM06"],
            severity=Severity.CRITICAL if tool_name in ("exec", "eval", "bash", "shell") else Severity.HIGH,
            title=f"Excessive Agency: High-Privilege Agent Tool '{tool_name}'",
            description=(
                f"Agent exposes high-privilege action '{tool_name}' without explicit human-in-the-loop "
                "confirmation gates, capability scoping, or tenant isolation boundaries."
            ),
            file_path=path,
            line_number=line,
            vulnerable_snippet=snippet,
            recommended_fix=(
                "Enforce human-in-the-loop verification, restrict tool permissions to least privilege, "
                "and apply strict tenant authorization checks before executing high-privilege tools."
            ),
            cwe_id="CWE-250",
        ))

    # Check 3: LLM02 - Unmasked Credential Forwarding to LLM Context
    for m in AUTH_HEADER_FORWARD.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(Finding(
            owasp_id="LLM02",
            owasp_name=OWASP_LLM_CATEGORIES["LLM02"],
            severity=Severity.HIGH,
            title="Sensitive Credential Exposure in Agent Context",
            description=(
                "Authentication headers or raw bearer tokens are forwarded into agent conversational "
                "context or LLM message payloads, risking leakage via tool output or model generation."
            ),
            file_path=path,
            line_number=line,
            vulnerable_snippet=snippet,
            recommended_fix=(
                "Redact Authorization/Bearer tokens before passing context to LLMs. Store credentials "
                "in secure session state and reference them via opaque session IDs."
            ),
            cwe_id="CWE-200",
        ))

    # Check 4: LLM06 / LLM07 - Permissive MCP Input Schema
    for m in MCP_OPEN_SCHEMA.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(Finding(
            owasp_id="LLM06",
            owasp_name=OWASP_LLM_CATEGORIES["LLM06"],
            severity=Severity.MEDIUM,
            title="Unconstrained MCP Tool Input Schema",
            description=(
                "MCP tool declares an unconstrained object schema without defining required properties "
                "or validation bounds, enabling schema poisoning and unexpected argument injection."
            ),
            file_path=path,
            line_number=line,
            vulnerable_snippet=snippet,
            recommended_fix=(
                "Define explicit JSON schema properties, enum constraints, and required fields for all "
                "MCP tools to prevent unexpected input injection."
            ),
            cwe_id="CWE-20",
        ))

    return findings


def scan_agentic_threats(files: dict[str, str]) -> list[Finding]:
    """Scan an entire repository file map for agentic protocol and LLM security threats."""
    findings: list[Finding] = []
    for path, content in files.items():
        findings.extend(analyze_agentic_code(path, content))
    return findings
