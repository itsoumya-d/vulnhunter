"""Tests for the Agentic Protocol and MCP Security Analyzer."""

from backend.agentic_guard import analyze_agentic_code, scan_agentic_threats
from backend.scanner import OWASP_CATEGORIES, Severity


def test_detects_prompt_injection_sink():
    code = '''
def handle_chat(user_input: str):
    system_prompt = f"You are an assistant. User instructions: {user_input}"
    return call_model(system_prompt)
'''
    findings = analyze_agentic_code("agent.py", code)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "LLM01"
    assert f.severity == Severity.HIGH
    assert f.line_number == 3
    assert "Prompt Injection" in f.title
    assert f.cwe_id == "CWE-77"
    assert f.owasp_id in OWASP_CATEGORIES


def test_detects_high_risk_tool_declaration():
    code = '''
tools = [
    {"name": "bash", "description": "Run shell commands"},
    {"tool_name": "delete_tenant", "description": "Drop tenant records"}
]
'''
    findings = analyze_agentic_code("tools.py", code)
    assert len(findings) == 2
    assert findings[0].owasp_id == "LLM06"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[1].owasp_id == "LLM06"
    assert findings[1].severity == Severity.HIGH


def test_detects_credential_leakage_in_context():
    code = '''
def prepare_agent_context(req):
    messages.append({"authorization": req.headers.get("Authorization")})
'''
    findings = analyze_agentic_code("orchestrator.py", code)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "LLM02"
    assert f.severity == Severity.HIGH
    assert "Sensitive Credential Exposure" in f.title
    assert f.cwe_id == "CWE-200"


def test_detects_permissive_mcp_input_schema():
    code = '''
mcp_tool = {
    "name": "lookup",
    "inputSchema": {"type": "object"}
}
'''
    findings = analyze_agentic_code("mcp_server.py", code)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "LLM06"
    assert f.severity == Severity.MEDIUM
    assert "MCP Tool Input Schema" in f.title


def test_clean_code_has_no_findings():
    code = '''
def compute_metrics(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0
'''
    findings = analyze_agentic_code("utils.py", code)
    assert findings == []


def test_empty_content_returns_empty_findings():
    assert analyze_agentic_code("empty.py", "") == []
    assert analyze_agentic_code("whitespace.py", "   \n\t  ") == []


def test_scan_agentic_threats_multi_file():
    files = {
        "safe.py": "x = 42\n",
        "vuln_agent.py": 'system_prompt = f"System: {query}"\n',
        "mcp_config.json": '{"inputSchema": {"type": "object"}}\n',
    }
    findings = scan_agentic_threats(files)
    assert len(findings) == 2
    paths = {f.file_path for f in findings}
    assert paths == {"vuln_agent.py", "mcp_config.json"}
