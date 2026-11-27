"""
Network Protocol and Edge Communication Security Guard (OWASP Top 10 / CWE).
Detects cleartext network transmission, insecure socket bindings,
disabled TLS certificate verification, and exposed management protocols.
"""

from __future__ import annotations

import re

from backend.scanner import Finding, OWASP_CATEGORIES, Severity

# Insecure cleartext transport protocols
CLEARTEXT_PROTOCOL = re.compile(
    r"\b(?:telnetlib\.Telnet|ftplib\.FTP|http\.client\.HTTPConnection)\b|['\"]http://(?!localhost|127\.0\.0\.1)[^\s'\"<>]+['\"]|['\"]ws://(?!localhost|127\.0\.0\.1)[^\s'\"<>]+['\"]",
    re.IGNORECASE,
)

# Insecure socket binding to all interfaces (0.0.0.0 or empty string)
INSECURE_BINDING = re.compile(
    r"\.bind\s*\(\s*\(\s*['\"](?:0\.0\.0\.0|)['\"]\s*,\s*\d+\s*\)\s*\)",
    re.IGNORECASE,
)

# Disabled TLS / SSL certificate verification
DISABLED_TLS_VERIFY = re.compile(
    r"\bverify\s*=\s*False\b|\bssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b|\bssl\.PROTOCOL_TLSv1(?:_\d)?\b",
    re.IGNORECASE,
)

# Insecure SNMP v1/v2c community string or raw default management protocol
INSECURE_MANAGEMENT = re.compile(
    r"(?:['\"]?community['\"]?\s*[:=]\s*['\"](?:public|private)['\"])|(?:['\"](?:public|private)['\"]\s*,\s*['\"]?version['\"]?\s*[:=]\s*[12]\b)|snmp(?:v1|v2c)\b",
    re.IGNORECASE,
)


def _find_line_number(content: str, match_pos: int) -> int:
    return content[:match_pos].count("\n") + 1


def _extract_snippet(content: str, line_no: int, num_lines: int = 3) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1)
    end = min(len(lines), start + num_lines)
    return "\n".join(lines[start:end])


def analyze_network_code(path: str, content: str) -> list[Finding]:
    """Analyze source code or network service manifests for insecure transport and socket configurations."""
    findings: list[Finding] = []
    if not content.strip():
        return findings

    # Check 1: A02 - Cleartext Network Transmission (CWE-319)
    for m in CLEARTEXT_PROTOCOL.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(
            Finding(
                owasp_id="A02",
                owasp_name=OWASP_CATEGORIES.get("A02", "Cryptographic Failures"),
                severity=Severity.HIGH,
                title="Cleartext Network Protocol in Transport Layer",
                description=(
                    f"File '{path}' uses unencrypted transport protocol ('{m.group(0)[:60]}'). "
                    "Cleartext traffic is susceptible to passive interception and MITM manipulation."
                ),
                file_path=path,
                line_number=line,
                vulnerable_snippet=snippet,
                recommended_fix="Enforce encrypted communication protocols (TLS/HTTPS/WSS/SSH) with mutual authentication.",
                cwe_id="CWE-319",
            )
        )

    # Check 2: A07 - Disabled TLS/SSL Certificate Verification (CWE-295)
    for m in DISABLED_TLS_VERIFY.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(
            Finding(
                owasp_id="A07",
                owasp_name=OWASP_CATEGORIES.get("A07", "Identification and Authentication Failures"),
                severity=Severity.CRITICAL,
                title="TLS Certificate Validation Disabled",
                description=(
                    f"File '{path}' disables TLS certificate or hostname verification ('{m.group(0)}'). "
                    "This exposes network traffic to trivial interception and adversary impersonation."
                ),
                file_path=path,
                line_number=line,
                vulnerable_snippet=snippet,
                recommended_fix="Enable strict TLS certificate validation (verify=True, ssl.CERT_REQUIRED) and verify hostnames.",
                cwe_id="CWE-295",
            )
        )

    # Check 3: A05 - Insecure Socket Binding to All Interfaces (CWE-284)
    for m in INSECURE_BINDING.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(
            Finding(
                owasp_id="A05",
                owasp_name=OWASP_CATEGORIES.get("A05", "Security Misconfiguration"),
                severity=Severity.MEDIUM,
                title="Insecure Socket Interface Binding",
                description=(
                    f"Socket binds to all network interfaces ('{m.group(0)}'). "
                    "Edge services should bind exclusively to loopback or explicit private VLAN interfaces."
                ),
                file_path=path,
                line_number=line,
                vulnerable_snippet=snippet,
                recommended_fix="Bind network services to 127.0.0.1 or designated private network interfaces.",
                cwe_id="CWE-284",
            )
        )

    # Check 4: A05 - Legacy Management Protocol or Default Community String (CWE-200)
    for m in INSECURE_MANAGEMENT.finditer(content):
        line = _find_line_number(content, m.start())
        snippet = _extract_snippet(content, line)
        findings.append(
            Finding(
                owasp_id="A05",
                owasp_name=OWASP_CATEGORIES.get("A05", "Security Misconfiguration"),
                severity=Severity.HIGH,
                title="Legacy Insecure Network Management Configuration",
                description=(
                    f"File '{path}' configures legacy unencrypted management credentials ('{m.group(0)}'). "
                    "SNMP v1/v2c community strings transmit in cleartext across the local network."
                ),
                file_path=path,
                line_number=line,
                vulnerable_snippet=snippet,
                recommended_fix="Upgrade to SNMPv3 with USM authentication and privacy encryption, or modern SSH/gRPC telemetry.",
                cwe_id="CWE-200",
            )
        )

    return findings


def scan_network_threats(files: dict[str, str]) -> list[Finding]:
    """Scan all provided files for network and edge protocol vulnerabilities."""
    all_findings: list[Finding] = []
    for path, content in files.items():
        all_findings.extend(analyze_network_code(path, content))
    return all_findings
