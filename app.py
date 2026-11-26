from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import os
import sqlite3
import sys
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

FREE_TIER_LIMIT = 20
MICRO_SCALE = Decimal(1_000_000)
MCP_PROTOCOL_VERSION = "2025-11-25"

VERIFY_INVOICE_TOOL_SCHEMA: dict[str, Any] = {
    "name": "verify_invoice_batch",
    "description": (
        "Audit a batch of invoices using exact 128-bit micro-dollar Decimal ROUND_HALF_EVEN "
        "arithmetic, SHA-256 duplicate detection, SHA-256 Merkle root generation, and Benford first-digit chi-square scoring."
    ),
    "inputSchema": {
        "type": "object",
        "required": ["invoices"],
        "properties": {
            "invoices": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["total_usd"],
                    "properties": {
                        "id": {"type": "string"},
                        "vendor": {"type": "string"},
                        "total_usd": {"type": ["string", "number"]},
                        "expected_usd": {"type": ["string", "number"]},
                        "line_items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["qty", "unit_price_usd"],
                                "properties": {
                                    "qty": {"type": ["integer", "number", "string"]},
                                    "unit_price_usd": {"type": ["string", "number"]},
                                },
                            },
                        },
                    },
                },
            }
        },
    },
}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_micro_usd(raw: str | float) -> int:
    clean = str(raw).strip().replace("$", "").replace(",", "")
    d = Decimal(clean)
    return int((d * MICRO_SCALE).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root_hex(leaves: list[str]) -> str:
    if not leaves:
        return sha256_hex(b"")
    layer = [hashlib.sha256(b"\x00" + leaf.encode("utf-8")).digest() for leaf in leaves]
    while len(layer) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        layer = nxt
    return layer[0].hex()


def verify_invoice_batch(invoices: list[dict[str, Any]]) -> dict[str, Any]:
    if not invoices:
        raise ValueError("invoices list cannot be empty")
    seen_hashes: set[str] = set()
    duplicates: list[str] = []
    math_errors: list[dict[str, Any]] = []
    leaves: list[str] = []
    total_micro = 0
    first_digit_counts = [0] * 9

    for idx, inv in enumerate(invoices):
        inv_id = str(inv.get("id", f"ROW-{idx}"))
        vendor = str(inv.get("vendor", "UNKNOWN")).strip()
        stated_micro = to_micro_usd(inv["total_usd"])
        lines = inv.get("line_items") or []
        if lines:
            computed_micro = sum(
                int(
                    (
                        Decimal(str(li["qty"]))
                        * Decimal(str(li["unit_price_usd"]).replace("$", "").replace(",", ""))
                        * MICRO_SCALE
                    ).quantize(Decimal(1), rounding=ROUND_HALF_EVEN)
                )
                for li in lines
            )
            if computed_micro != stated_micro:
                math_errors.append({
                    "id": inv_id,
                    "stated_micro": str(stated_micro),
                    "computed_micro": str(computed_micro),
                    "drift_micro": str(stated_micro - computed_micro),
                })
        elif inv.get("expected_usd") not in (None, ""):
            expected_micro = to_micro_usd(inv["expected_usd"])
            if expected_micro != stated_micro:
                math_errors.append({
                    "id": inv_id,
                    "stated_micro": str(stated_micro),
                    "computed_micro": str(expected_micro),
                    "drift_micro": str(stated_micro - expected_micro),
                })

        canonical = f"{inv_id}|{vendor.lower()}|{stated_micro}"
        digest = sha256_hex(canonical.encode("utf-8"))
        if digest in seen_hashes:
            duplicates.append(inv_id)
        seen_hashes.add(digest)
        leaves.append(canonical)
        total_micro += stated_micro

        if stated_micro > 0:
            lead = str(abs(stated_micro)).lstrip("0")
            if lead and lead[0] in "123456789":
                first_digit_counts[int(lead[0]) - 1] += 1

    n_pos = sum(first_digit_counts)
    benford_chi2 = 0.0
    if n_pos > 0:
        for d in range(1, 10):
            exp = n_pos * math.log10(1.0 + 1.0 / d)
            obs = first_digit_counts[d - 1]
            benford_chi2 += ((obs - exp) ** 2) / exp

    return {
        "invoice_count": len(invoices),
        "total_micro_usd": str(total_micro),
        "total_usd": f"${(Decimal(total_micro) / MICRO_SCALE).quantize(Decimal('0.01'), rounding=ROUND_HALF_EVEN):,.2f}",
        "merkle_root_sha256": merkle_root_hex(leaves),
        "duplicate_ids": duplicates,
        "math_errors": math_errors,
        "benford_chi2": round(benford_chi2, 4),
        "clean": len(duplicates) == 0 and len(math_errors) == 0,
    }


def load_invoices_from_file(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Audit file not found: {path}")
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("invoices"), list):
        return data["invoices"]
    raise ValueError("JSON input must be a list of invoices or {'invoices': [...]}")


class MeteredStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    api_key TEXT PRIMARY KEY,
                    tier TEXT NOT NULL DEFAULT 'free',
                    docs_used INTEGER NOT NULL DEFAULT 0,
                    stripe_customer_id TEXT DEFAULT '',
                    updated_utc TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def check_and_consume(self, api_key: str, count: int) -> tuple[bool, dict[str, Any]]:
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE api_key = ?", (api_key,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO api_keys (api_key, tier, docs_used, updated_utc) VALUES (?, 'free', 0, ?)",
                    (api_key, now),
                )
                tier, used = "free", 0
            else:
                tier, used = str(row["tier"]), int(row["docs_used"])

            if tier == "free" and (used + count) > FREE_TIER_LIMIT:
                return False, {
                    "tier": tier,
                    "docs_used": used,
                    "free_limit": FREE_TIER_LIMIT,
                    "requested": count,
                }

            conn.execute(
                "UPDATE api_keys SET docs_used = ?, updated_utc = ? WHERE api_key = ?",
                (used + count, now, api_key),
            )
            conn.commit()
            return True, {"tier": tier, "docs_used": used + count, "free_limit": FREE_TIER_LIMIT}

    def upgrade_key(self, api_key: str, tier: str = "pro_monthly", customer_id: str = "") -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO api_keys (api_key, tier, docs_used, stripe_customer_id, updated_utc)
                VALUES (?, ?, 0, ?, ?)
                ON CONFLICT(api_key) DO UPDATE SET
                    tier=excluded.tier,
                    stripe_customer_id=excluded.stripe_customer_id,
                    updated_utc=excluded.updated_utc
                """,
                (api_key, tier, customer_id, now),
            )
            conn.commit()


def verify_stripe_hmac(payload: bytes, sig_header: str, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header.strip())


def upgrade_plans_payload(payment_link: str) -> dict[str, str]:
    return {
        "monthly_subscription": "$29.00/mo unlimited up to 2,500 docs",
        "metered_per_doc": "$0.05/verified document",
        "checkout_url": payment_link,
    }


def make_handler(store: MeteredStore, webhook_secret: str, payment_link: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, code: int, payload: Any) -> None:
            raw = b"" if payload is None else json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(code)
            if payload is not None:
                self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/health":
                self._send(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "mcp_protocol": MCP_PROTOCOL_VERSION,
                        "free_doc_limit": FREE_TIER_LIMIT,
                        "pricing": "$29/mo or $0.05/doc",
                    },
                )
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def _handle_mcp(self, raw: bytes, api_key: str) -> None:
            try:
                rpc = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
                return

            req_id = rpc.get("id")
            method = str(rpc.get("method", ""))
            params = rpc.get("params") or {}

            if method == "notifications/initialized":
                self._send(HTTPStatus.ACCEPTED, None)
                return

            if method == "initialize":
                self._send(
                    HTTPStatus.OK,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": "invoice-audit-mcp-saas", "version": "1.0.0"},
                        },
                    },
                )
                return

            if method == "tools/list":
                self._send(
                    HTTPStatus.OK,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"tools": [VERIFY_INVOICE_TOOL_SCHEMA]},
                    },
                )
                return

            if method == "tools/call":
                tool_name = str(params.get("name", ""))
                args = params.get("arguments") or {}
                if tool_name != "verify_invoice_batch":
                    self._send(
                        HTTPStatus.NOT_FOUND,
                        {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}},
                    )
                    return

                invoices = args.get("invoices") or []
                if not isinstance(invoices, list) or not invoices:
                    self._send(
                        HTTPStatus.BAD_REQUEST,
                        {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "invoices list cannot be empty"}},
                    )
                    return

                allowed, meter = store.check_and_consume(api_key, len(invoices))
                if not allowed:
                    self._send(
                        HTTPStatus.PAYMENT_REQUIRED,
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32002,
                                "message": "Free tier quota exceeded (20 documents free).",
                                "data": {"meter": meter, "upgrade_plans": upgrade_plans_payload(payment_link)},
                            },
                        },
                    )
                    return

                try:
                    audit = verify_invoice_batch(invoices)
                except (ValueError, KeyError, TypeError) as exc:
                    self._send(
                        HTTPStatus.BAD_REQUEST,
                        {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(exc)}},
                    )
                    return

                payload = {"meter": meter, "audit": audit}
                self._send(
                    HTTPStatus.OK,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(payload)}],
                            "structuredContent": payload,
                            "isError": False,
                        },
                    },
                )
                return

            self._send(
                HTTPStatus.BAD_REQUEST,
                {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unsupported method: {method}"}},
            )

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(min(length, 2 * 1024 * 1024))

            if path == "/mcp":
                api_key = self.headers.get("X-API-Key", "anon-trial").strip() or "anon-trial"
                self._handle_mcp(raw, api_key)
                return

            if path == "/v1/webhooks/stripe":
                sig = self.headers.get("X-Stripe-Signature", "")
                if not verify_stripe_hmac(raw, sig, webhook_secret):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "Invalid webhook signature"})
                    return
                ev = json.loads(raw.decode("utf-8"))
                api_key = str(ev.get("api_key", "")).strip()
                if not api_key:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": "Missing api_key"})
                    return
                store.upgrade_key(api_key, tier=str(ev.get("tier", "pro_monthly")), customer_id=str(ev.get("customer_id", "")))
                self._send(HTTPStatus.OK, {"upgraded": True, "api_key": api_key})
                return

            if path == "/v1/verify":
                api_key = self.headers.get("X-API-Key", "anon-trial").strip()
                try:
                    body = json.loads(raw.decode("utf-8"))
                    invoices = body.get("invoices") or []
                    allowed, meter = store.check_and_consume(api_key, len(invoices))
                    if not allowed:
                        self._send(
                            HTTPStatus.PAYMENT_REQUIRED,
                            {
                                "error": "Free tier quota exceeded (20 documents free).",
                                "meter": meter,
                                "upgrade_plans": upgrade_plans_payload(payment_link),
                            },
                        )
                        return
                    result = verify_invoice_batch(invoices)
                    self._send(HTTPStatus.OK, {"meter": meter, "audit": result})
                except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            self._send(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    return Handler


def create_server(host: str = "127.0.0.1", port: int = 8088, db_path: Path | None = None, webhook_secret: str | None = None) -> ThreadingHTTPServer:
    resolved_db = db_path or (Path(__file__).resolve().parent / "data" / "meter.db")
    secret = webhook_secret or os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_local_dev_only")
    link = os.environ.get("STRIPE_PAYMENT_LINK", "https://buy.stripe.com/configure_live_link")
    return ThreadingHTTPServer((host, port), make_handler(MeteredStore(resolved_db), secret, link))


def run_cli(audit_file: Path, out_file: Path | None = None) -> int:
    invoices = load_invoices_from_file(audit_file)
    report = verify_invoice_batch(invoices)
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if out_file is not None:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["clean"] else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="128-bit Invoice Audit REST/MCP Micro-SaaS and CI CLI")
    parser.add_argument("--audit-file", type=Path, help="Run offline invoice audit against JSON or CSV file")
    parser.add_argument("--out", type=Path, help="Optional JSON report output file")
    args = parser.parse_args(argv)

    if args.audit_file is not None:
        return run_cli(args.audit_file, args.out)

    srv = create_server(host="0.0.0.0" if os.environ.get("PORT") else "127.0.0.1", port=int(os.environ.get("PORT", "8088")))
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
