# `invoice-audit-mcp-saas`

Zero-dependency Python 3.12 REST API, MCP `2025-11-25` Streamable HTTP server, and GitHub Action for exact 128-bit micro-dollar invoice auditing, SHA-256 Merkle root generation, duplicate hashing, and Benford first-digit conformity checks.

Live browser calculator: [Open Benford Invoice Audit Tool](https://nahianakhtar.github.io/tools/benford-invoice-audit/)

## Why teams use it

- Eliminates IEEE-754 floating-point penny drift by scaling currency values to integer micro-dollars (`10^-6 USD`) with `Decimal` `ROUND_HALF_EVEN`.
- Ships native **HTTP 402 Payment Required** metering in embedded SQLite WAL (`20` free audited invoices per key, upgraded immediately by Stripe HMAC-SHA256 webhooks).
- Runs with zero third-party Python runtime dependencies using Python stdlib (`http.server`, `sqlite3`, `decimal`, `hashlib`, `hmac`).
- Exposes three execution modes from one file (`app.py`): REST JSON (`POST /v1/verify`), MCP Streamable HTTP (`POST /mcp`), and CI batch CLI (`--audit-file`).

## Endpoints & Metering

| Interface | Path / Flag | Purpose |
| :--- | :--- | :--- |
| Health Probe | `GET /health` | Confirms live service, MCP protocol version, and quota policy |
| REST Batch Audit | `POST /v1/verify` | Audits `{"invoices": [...]}` and returns HTTP 402 over 20 free docs |
| MCP 2025-11-25 HTTP | `POST /mcp` | Handles `initialize`, `tools/list`, and metered `verify_invoice_batch` |
| Stripe Webhook | `POST /v1/webhooks/stripe` | Verifies `X-Stripe-Signature` HMAC-SHA256 and upgrades key tier |
| GitHub Action / CLI | `python3 app.py --audit-file` | Checks JSON or CSV batches in CI and exits `2` on drift or duplicates |

## Quickstart

```bash
python3 app.py
# Or test locally:
ruff check . && PYTHONPATH=. pytest -q
```

## GitHub Action Usage

```yaml
- uses: nahianakhtar/invoice-audit-mcp-saas@v1.0.0
  with:
    audit_file: invoices.csv
    out_file: audit-report.json
```

## Container Build

```bash
docker build -t invoice-audit-mcp-saas:1.0.0 .
docker run --rm -p 8080:8080 -e STRIPE_WEBHOOK_SECRET=your_secret invoice-audit-mcp-saas:1.0.0
```
