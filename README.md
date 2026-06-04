# redops

**Red Team Campaign Manager + OPSEC Validator** — Structured engagement management, MITRE ATT&CK TTP tracking, 9-check OPSEC validation, and auto-generated reports (HTML, PDF, DOCX).

[![CI](https://github.com/dragonday3/redops/actions/workflows/ci.yml/badge.svg)](https://github.com/dragonday3/redops/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Authorized use only.** This tool is a management layer for authorized red team engagements. It contains no C2, implants, or exploit delivery.

---

## What It Does

redops helps red team operators manage the lifecycle of authorized engagements:

- **Campaign management** — scoped engagements, objectives, operator assignment
- **TTP tracking** — MITRE ATT&CK technique logging with phase and status
- **Operator log** — structured timestamped entries (action, target, result, evidence refs)
- **OPSEC validation** — 9-check engine against your *own* infrastructure before engagement
- **Report generation** — executive + technical reports in HTML, PDF, DOCX, or JSON
- **REST API** — full CRUD via FastAPI
- **Python SDK** — programmatic access

---

## Install

### From source
```bash
git clone https://github.com/dragonday3/redops
cd redops
pip install -e ".[dev]"
```

### Docker
```bash
docker compose up -d     # starts API on :8000
```

---

## Quick Start

### 1. Create an engagement
```bash
redops engagement create \
  --name "Op Nightfall" \
  --client "ACME Corp" \
  --start 2024-01-15 \
  --end 2024-02-15 \
  --operator alice \
  --operator bob
```

### 2. Add TTPs
```bash
redops ttp add <engagement_id> \
  --technique T1566.001 \
  --name "Spearphishing Attachment" \
  --tactic "Initial Access" \
  --phase "Week 1"
```

### 3. Log operator actions
```bash
redops log add <engagement_id> \
  --operator alice \
  --action "Sent phishing email" \
  --target "user@acme.com" \
  --result success \
  --technique T1566.001
```

### 4. Run OPSEC checks on your infra
```bash
redops opsec run c2.yourdomain.com --vt-key $VT_API_KEY
```

Output: scored OPSEC report. Exit 1 if grade D or F.

### 5. Generate report
```bash
redops report generate <engagement_id> --format html --out-file report.html
redops report generate <engagement_id> --format pdf  --out-file report.pdf
redops report generate <engagement_id> --format docx --out-file report.docx
```

---

## CLI Reference

```
redops engagement create  --name X --client Y --start YYYY-MM-DD --end YYYY-MM-DD [--operator NAME ...]
redops engagement list
redops engagement show <id>

redops objective add     <engagement_id> --title X [--type primary|secondary] [--description X]
redops objective complete <engagement_id> <objective_id>

redops ttp add   <engagement_id> --technique T1566.001 [--name X] [--tactic X] [--phase X]
redops ttp list  <engagement_id>

redops log add   <engagement_id> --operator X --action X --target X --result success|failure|partial|unknown
redops log show  <engagement_id>

redops opsec run <domain> [--vt-key KEY]

redops report generate <engagement_id> --format json|html|pdf|docx --out-file PATH

redops serve [--host 127.0.0.1] [--port 8000]
```

---

## OPSEC Checks

| Check | Method | Pass Condition |
|-------|--------|----------------|
| `domain_age` | WHOIS | Domain > 30 days old |
| `vt_reputation` | VirusTotal API | 0 malicious/suspicious |
| `ct_exposure` | crt.sh | No unexpected certs indexed |
| `ssl_validity` | TLS socket | Valid cert, ≥14 days to expiry |
| `spf_record` | DNS TXT | SPF record present |
| `dkim_record` | DNS TXT | DKIM record present |
| `dmarc_record` | DNS TXT | DMARC with p=reject/quarantine |
| `http_redirect` | httpx | Redirector chain resolves ≤500 |
| `open_ports` | socket | No unexpected ports open |

Score: 0–100. Grade: A≥90 / B≥75 / C≥60 / D≥45 / F<45. Exit code 1 if D or F.

---

## REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET/POST | /engagements | List / create engagements |
| GET/PATCH/DELETE | /engagements/{id} | Get / update / delete |
| GET/POST | /engagements/{id}/objectives | List / add objectives |
| PATCH | /engagements/{id}/objectives/{oid} | Update objective |
| GET/POST | /engagements/{id}/ttps | List / add TTPs |
| PATCH | /engagements/{id}/ttps/{tid} | Update TTP |
| GET/POST | /engagements/{id}/log | Get / add log entries |
| POST | /engagements/{id}/opsec | Run OPSEC checks |
| GET | /engagements/{id}/opsec | List OPSEC results |
| POST | /engagements/{id}/report?format=json\|html\|pdf\|docx | Generate report |

### Start API server
```bash
redops serve --host 0.0.0.0 --port 8000
# or via Docker Compose
docker compose up -d
```

---

## Python SDK

```python
import asyncio
from datetime import date
from redops.sdk import RedOps
from redops.models.engagement import Engagement

async def main():
    ops = RedOps("sqlite+aiosqlite:///./redops.db")

    # Create engagement
    eng = await ops.create_engagement(Engagement(
        name="Op Nightfall",
        client="ACME Corp",
        start_date=date(2024, 1, 15),
        end_date=date(2024, 2, 15),
        operators=["alice"],
    ))

    # Run OPSEC checks
    result = await ops.opsec("c2.yourdomain.com")
    print(f"OPSEC Grade: {result.grade} ({result.score}/100)")

    # Generate HTML report
    html = await ops.report(eng.id, fmt="html", out_path="report.html")

    await ops.close()

asyncio.run(main())
```

---

## Architecture

```
CLI (Typer + Rich)
  ├── engagement / objective / ttp / log / opsec / report / serve

REST API (FastAPI)
  ├── CRUD endpoints for all entities
  └── Report generation (streaming response)

OPSEC Engine
  ├── 9 async checks (domain age, VT, CT logs, SSL, SPF/DKIM/DMARC, HTTP, ports)
  └── Scoring: 0-100, grade A-F

MITRE ATT&CK Client
  ├── Local JSON cache (~/.redops/mitre_cache.json, 7-day TTL)
  └── search / get / tactics

Report Generator
  ├── HTML (Jinja2, dark-theme, self-contained)
  ├── PDF (WeasyPrint from HTML template)
  ├── DOCX (python-docx)
  └── JSON (Pydantic model_dump_json)

Storage (SQLAlchemy 2.0 async, SQLite/PostgreSQL)
  └── 5 tables: engagements, objectives, ttps, log_entries, opsec_results
```

---

## Development

```bash
git clone https://github.com/dragonday3/redops
cd redops
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with coverage
pytest --cov=redops --cov-report=term-missing tests/

# Start API (dev)
redops serve --host 127.0.0.1 --port 8000
```

Test matrix: Python 3.10, 3.11, 3.12 (CI runs all three on every push).

---

## Data Sources

- **WHOIS** — domain age via `python-whois`
- **VirusTotal** — free API (`x-apikey` header), optional
- **crt.sh** — Certificate Transparency logs, public
- **Shodan InternetDB** — free endpoint, no key needed
- **MITRE ATT&CK** — STIX bundle from GitHub, cached locally

---

## License

MIT

---

> This tool is designed for authorized red team engagements only. Always obtain written authorization before testing any target. The authors are not responsible for unauthorized or illegal use.
