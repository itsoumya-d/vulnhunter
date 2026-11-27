"""Tests for the Network Protocol and Edge Communication Security Guard."""

from backend.network_guard import analyze_network_code, scan_network_threats
from backend.scanner import Severity


def test_detects_cleartext_http_and_telnet():
    code = '''
import telnetlib

def connect_switch():
    tn = telnetlib.Telnet("192.168.1.1")
    endpoint = "http://remote-switch.net/api"
    return tn, endpoint
'''
    findings = analyze_network_code("switch.py", code)
    assert len(findings) == 2
    assert findings[0].owasp_id == "A02"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe_id == "CWE-319"
    assert "Cleartext Network Protocol" in findings[0].title


def test_ignores_localhost_cleartext():
    code = '''
def local_endpoint():
    return "http://localhost:8000/metrics", "http://127.0.0.1:9090"
'''
    findings = analyze_network_code("local.py", code)
    assert len(findings) == 0


def test_detects_disabled_tls_verification():
    code = '''
import httpx
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

resp = httpx.get("https://internal.lan", verify=False)
'''
    findings = analyze_network_code("client.py", code)
    assert len(findings) >= 2
    f_cert = next(f for f in findings if f.cwe_id == "CWE-295")
    assert f_cert.severity == Severity.CRITICAL
    assert f_cert.owasp_id == "A07"


def test_detects_insecure_wildcard_binding():
    code = '''
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 8080))
s.listen(5)
'''
    findings = analyze_network_code("server.py", code)
    assert len(findings) == 1
    assert findings[0].owasp_id == "A05"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].cwe_id == "CWE-284"


def test_detects_insecure_snmp_community():
    code = '''
# Network management config
snmp_config = {"community": "public", "version": 2}
'''
    findings = analyze_network_code("snmp.py", code)
    assert len(findings) == 1
    assert findings[0].owasp_id == "A05"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe_id == "CWE-200"


def test_scan_network_threats_multi_file():
    files = {
        "net.py": "s.bind(('0.0.0.0', 9000))",
        "safe.py": "import ssl\nctx.verify_mode = ssl.CERT_REQUIRED",
    }
    findings = scan_network_threats(files)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-284"
