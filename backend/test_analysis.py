"""Offline regressions: synthetic source and provider replies only."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.scanner import ScanResult, VulnScanner


def finding(**changes):
    item = {
        "owasp_id": "A05", "owasp_name": "Security Misconfiguration",
        "severity": "LOW", "title": "Synthetic fixture finding",
        "description": "A fixture used only to validate result handling.",
        "line_number": 1, "vulnerable_snippet": "fixture = True",
        "recommended_fix": "Review the fixture.", "cwe_id": None,
    }
    return item | changes


def response(raw="[]", *, stop_reason="end_turn", content=None):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=raw)] if content is None else content,
        stop_reason=stop_reason,
    )


def scanner_with(reply, files=None):
    scanner = VulnScanner.__new__(VulnScanner)
    scanner._gh = SimpleNamespace(fetch_repo_files=AsyncMock(return_value=(
        files or {"fixture.py": "fixture = True"}
    )))
    create = AsyncMock(side_effect=reply) if isinstance(reply, Exception) else AsyncMock(return_value=reply)
    scanner._ai = SimpleNamespace(messages=SimpleNamespace(create=create))
    return scanner


@pytest.mark.parametrize("reply", [
    RuntimeError("synthetic provider failure"),
    response("not JSON"),
    response("{}"),
    response("null"),
    response('["not a finding"]'),
    response('[{}]'),
    response(json.dumps([finding(severity="INVALID")])),
    response(json.dumps([finding(owasp_id="A00")])),
    response(json.dumps([finding(title=17)])),
    response(json.dumps([finding(line_number=True)])),
    response(json.dumps([finding(line_number=-1)])),
    response(json.dumps([finding(cwe_id=[])])),
    response(content=[]),
    response(content=[SimpleNamespace(type="tool_use", name="fixture")]),
    response("[]", stop_reason="max_tokens"),
    response("[]", stop_reason="refusal"),
    response("[]", stop_reason="pause_turn"),
])
def test_failed_analysis_cannot_be_clean(reply):
    scanner = scanner_with(reply)
    result = asyncio.run(scanner.scan("fixture/repository"))
    assert result.error
    assert result.risk_label == "INCOMPLETE"
    assert result.files_scanned == 0
    assert not result.findings
    assert "secure coding practices" not in result.scan_summary
    assert scanner._ai.messages.create.await_count == 1


@pytest.mark.parametrize("raw", ["[]", "```json\n[]\n```"])
def test_valid_empty_analysis_remains_a_completed_zero_finding_result(raw):
    scanner = scanner_with(response(raw))
    result = asyncio.run(scanner.scan("fixture/repository"))
    assert result.error is None
    assert result.files_scanned == 1
    assert result.risk_label == "CLEAN"
    assert "secure coding practices" not in result.scan_summary
    assert "not" in result.scan_summary.lower()  # explicitly not proof of security


def test_mixed_valid_and_invalid_items_fail_the_file_atomically():
    scanner = scanner_with(response(json.dumps([finding(), finding(severity="INVALID")])))
    result = asyncio.run(scanner.scan("fixture/repository"))
    assert result.error
    assert result.files_scanned == 0
    assert not result.findings


def test_partial_failure_preserves_successes_across_batches_without_success_summary():
    files = {f"fixture{i}.py": "fixture = True" for i in range(10)}
    scanner = scanner_with(response(), files)
    calls = []

    async def create(**kwargs):
        prompt = kwargs["messages"][0]["content"]
        calls.append(prompt)
        if "File: fixture1.py\n" in prompt:
            raise RuntimeError("synthetic failure: confidential upstream detail")
        if "File: fixture9.py\n" in prompt:
            return response(json.dumps([finding()]))
        return response()

    scanner._ai.messages.create.side_effect = create
    result = asyncio.run(scanner.scan("fixture/repository"))
    assert result.error
    assert "confidential upstream detail" not in result.error
    assert result.risk_label == "INCOMPLETE"
    assert result.files_scanned == 9
    assert len(result.findings) == 1
    assert result.findings[0].file_path == "fixture9.py"
    assert result.risk_score == 3
    assert len(calls) == 10  # summary generation is skipped for incomplete analysis


def test_successful_findings_and_summary_fallback_are_preserved():
    scanner = scanner_with(response())
    scanner._ai.messages.create.side_effect = [
        response(json.dumps([finding(severity="HIGH"), finding()])),
        RuntimeError("summary service unavailable"),
    ]
    result = asyncio.run(scanner.scan("fixture/repository"))
    assert result.error is None
    assert result.files_scanned == 1
    assert result.risk_score == 23
    assert [f.severity.value for f in result.findings] == ["HIGH", "LOW"]
    assert "Found 2 issue(s)" in result.scan_summary


def test_error_label_also_covers_fetch_failures():
    assert ScanResult("fixture/repository", "fixture/repository", 0, error="Fetch failed").risk_label == "INCOMPLETE"


def test_background_api_exposes_incomplete_status_and_result(monkeypatch):
    scanner = scanner_with(RuntimeError("synthetic provider error"))
    scanner.close = AsyncMock()
    monkeypatch.setattr(main, "VulnScanner", lambda **kwargs: scanner)
    monkeypatch.setattr(main, "_scan_cache", {"fixture": {
        "status": "pending", "repo_url": "fixture/repository", "result": None,
    }})
    asyncio.run(main._run_scan("fixture", "fixture/repository"))
    client = TestClient(main.app)
    assert client.get("/api/scan/fixture/status").json()["status"] == "error"
    result = client.get("/api/scan/fixture/result").json()
    assert result["error"]
    assert result["risk_label"] == "INCOMPLETE"
    assert result["files_scanned"] == 0
    scanner.close.assert_awaited_once()


def test_unexpected_background_failure_is_not_clean(monkeypatch):
    scanner = SimpleNamespace(scan=AsyncMock(side_effect=RuntimeError("fixture failure")), close=AsyncMock())
    monkeypatch.setattr(main, "VulnScanner", lambda **kwargs: scanner)
    monkeypatch.setattr(main, "_scan_cache", {"fixture": {"status": "pending"}})
    asyncio.run(main._run_scan("fixture", "fixture/repository"))
    assert main._scan_cache["fixture"]["result"].risk_label == "INCOMPLETE"


def test_absent_code_location_and_empty_snippet_are_valid_for_a_missing_control():
    scanner = scanner_with(response())
    scanner._ai.messages.create.side_effect = [
        response(json.dumps([finding(line_number=None, vulnerable_snippet="")])),
        response("Synthetic summary."),
    ]
    result = asyncio.run(scanner.scan("fixture/repository"))
    assert result.error is None
    assert result.findings[0].line_number is None
    assert result.findings[0].vulnerable_snippet == ""


def test_cancellation_is_propagated_instead_of_becoming_a_report():
    scanner = scanner_with(response())
    scanner._ai.messages.create.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scanner.scan("fixture/repository"))


def test_empty_fetch_error_still_marks_the_result_incomplete(monkeypatch):
    scanner = scanner_with(response())
    scanner._gh.fetch_repo_files.side_effect = RuntimeError()
    scanner.close = AsyncMock()
    monkeypatch.setattr(main, "VulnScanner", lambda **kwargs: scanner)
    monkeypatch.setattr(main, "_scan_cache", {"fixture": {"status": "pending"}})
    asyncio.run(main._run_scan("fixture", "fixture/repository"))
    assert main._scan_cache["fixture"]["status"] == "error"
    assert main._scan_cache["fixture"]["result"].risk_label == "INCOMPLETE"
    scanner._ai.messages.create.assert_not_awaited()


def test_api_preserves_partial_findings_and_counts(monkeypatch):
    scanner = scanner_with(response(), {"fixture1.py": "fixture = 1", "fixture2.py": "fixture = 2"})
    scanner._ai.messages.create.side_effect = [
        response(json.dumps([finding(severity="HIGH")])), RuntimeError("synthetic failure"),
    ]
    scanner.close = AsyncMock()
    monkeypatch.setattr(main, "VulnScanner", lambda **kwargs: scanner)
    monkeypatch.setattr(main, "_scan_cache", {"fixture": {
        "status": "pending", "repo_url": "fixture/repository", "result": None,
    }})
    asyncio.run(main._run_scan("fixture", "fixture/repository"))
    client = TestClient(main.app)
    assert client.get("/api/scan/fixture/status").json()["status"] == "error"
    result = client.get("/api/scan/fixture/result").json()
    assert result["error"]
    assert result["risk_label"] == "INCOMPLETE"
    assert result["files_scanned"] == 1
    assert len(result["findings"]) == 1
    assert result["high_count"] == 1
    assert result["owasp_breakdown"] == {"A05": 1}
    assert result["risk_score"] == 20
