"""Smoke tests for the VulnHunter FastAPI backend.

These run without an ANTHROPIC_API_KEY: they cover request validation and the
endpoints that never reach the model.
"""

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health_reports_ok():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "api_key_set" in body


def test_demo_repositories_listed():
    r = client.get("/api/demos")
    assert r.status_code == 200
    assert len(r.json()["demos"]) >= 1


def test_scan_rejects_non_github_url():
    r = client.post("/api/scan", json={"repo_url": "https://example.com/not-github"})
    assert r.status_code == 422


def test_scan_rejects_blank_url():
    r = client.post("/api/scan", json={"repo_url": "   "})
    assert r.status_code == 422


def test_scan_returns_503_without_api_key(monkeypatch):
    monkeypatch.setattr("backend.main.ANTHROPIC_API_KEY", "")
    r = client.post(
        "/api/scan",
        json={"repo_url": "https://github.com/itsoumya-d/autopilot-fde"},
    )
    assert r.status_code == 503


def test_unknown_scan_status_is_404():
    assert client.get("/api/scan/deadbeef/status").status_code == 404


def test_unknown_scan_result_is_404():
    assert client.get("/api/scan/deadbeef/result").status_code == 404
