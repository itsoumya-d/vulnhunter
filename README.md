# 🛡️ VulnHunter AI

**AI-powered OWASP security scanner for public GitHub repositories. Paste a repo URL → get a full vulnerability report in seconds.**

[![Powered by Anthropic Claude](https://img.shields.io/badge/Powered%20by-Anthropic%20Claude-blueviolet)](https://anthropic.com)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-red)](https://owasp.org/Top10/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🎯 What Is This?

Most security tools require local installation, CI/CD setup, or deep configuration before they're useful. VulnHunter has a different goal: **zero friction for a working scan**.

You enter a GitHub repo URL. That's it. VulnHunter fetches the code, passes it through Claude AI with OWASP Top 10 context, and returns a structured report with:

- **Risk score** (0–100) and executive summary
- **Per-finding details** with vulnerable code snippet + recommended fix
- **OWASP heatmap** showing which categories were hit
- **Severity filtering** (CRITICAL → HIGH → MEDIUM → LOW)

---

## 🚀 Quick Start

```bash
git clone https://github.com/your-username/vulnhunter
cd vulnhunter/backend
pip install -r requirements.txt
cp .env.example .env        # add ANTHROPIC_API_KEY
uvicorn main:app --reload   # starts at http://localhost:8000
```

Then open `http://localhost:8000` — the React frontend is served automatically.

**Or with Docker:**
```bash
docker build -t vulnhunter .
docker run -e ANTHROPIC_API_KEY=sk-ant-... -p 8000:8000 vulnhunter
```

### Demo repos to try

| Repo | What you'll find |
|------|-----------------|
| `github.com/digininja/DVWA` | SQL injection, XSS, CSRF, command injection |
| `github.com/WebGoat/WebGoat` | 20+ vulnerability types across Java/Spring |
| `github.com/OWASP/NodeGoat` | Node.js OWASP Top 10 examples |
| `github.com/erev0s/VAmPI` | Vulnerable REST API (Python/Flask) |

---

## 🏗 Architecture

```
Browser (React 18 SPA)
       │
       │  POST /api/scan        (start async scan)
       │  GET  /api/scan/{id}/status  (poll)
       │  GET  /api/scan/{id}/result  (fetch report)
       ▼
FastAPI Backend (Python 3.12)
  ├── GitHubFetcher
  │     └── GitHub Trees API (recursive)
  │         → filters to scannable file types
  │         → caps at 40 files, 80KB each
  │
  └── VulnScanner
        ├── Analyzes files in parallel batches of 8
        │   └── Claude Haiku (claude-haiku-4-5-20251001)
        │       OWASP-aware system prompt
        │       → structured JSON findings
        │
        ├── Generates executive summary (Claude Haiku)
        └── Computes weighted risk score (0–100)
```

---

## 📊 Risk Scoring

| Score | Label | Meaning |
|-------|-------|---------|
| 75–100 | CRITICAL | Immediate remediation required |
| 50–74  | HIGH     | Fix before next deployment |
| 25–49  | MEDIUM   | Schedule for next sprint |
| 1–24   | LOW      | Minor hardening improvements |
| 0      | CLEAN    | No findings detected |

**Score formula:** `min(100, Σ weights)` where CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=1 per finding.

---

## 📁 Project Structure

```
vulnhunter/
├── backend/
│   ├── scanner.py      ← GitHub fetcher + AI analysis engine
│   ├── main.py         ← FastAPI app (scan lifecycle, REST endpoints)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   └── index.html      ← Self-contained React 18 SPA
├── Dockerfile
├── README.md
└── LICENSE
```

---

## ⚙️ Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | ✅ | Anthropic API key — get one at console.anthropic.com |
| `GITHUB_TOKEN` | ❌ | Raises GitHub rate limit from 60 to 5,000 req/hr |

---

## 🔍 What Gets Scanned

VulnHunter scans Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C#, Rust, C/C++, shell scripts, Dockerfiles, and YAML/JSON/TOML configuration files.

Files are skipped if they are inside `node_modules`, `vendor`, or `dist` directories, are minified (`.min.js`), are lockfiles, or exceed 80KB.

Up to 40 files are analyzed per scan. For large monorepos, the most recently modified files are prioritized by the GitHub Trees API.

---

## 🤖 AI Design

VulnHunter uses `claude-haiku-4-5-20251001` for two tasks:

**File analysis** — A tightly constrained system prompt tells Claude to return only a JSON array of findings matching a strict schema. This ensures consistent, parseable output across all file types and languages. The schema covers OWASP category, severity, title, description, vulnerable snippet, recommended fix, and CWE ID.

**Executive summary** — After all file analyses complete, a second Claude call synthesizes the findings into a 3-sentence professional summary tailored to the repo name and finding counts.

Files are analyzed in parallel batches of 8, keeping total scan time under 30 seconds for typical repos.

---

## 🏆 Built For

**Quantum Sprint 2026** — Best Cybersecurity Tool category.

The thesis: enterprise-grade security scanning shouldn't require a SIEM, a dedicated AppSec team, or a week of setup. VulnHunter makes professional-quality OWASP analysis available to any developer in 30 seconds.

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

*Built by [Soumya Debnath](https://devpost.com/soumyadebnath1619) · Quantum Sprint 2026*
