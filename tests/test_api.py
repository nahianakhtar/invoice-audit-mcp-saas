from __future__ import annotations

import hashlib
import hmac
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from app import create_server, run_cli


def _post_json(url: str, payload: dict[str, object], headers: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(
        url,
        method="POST",
        headers=req_headers,
        data=json.dumps(payload).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8")
        return err.code, json.loads(raw) if raw else {}


def test_http_402_metering_stripe_webhook_and_mcp(tmp_path: Path) -> None:
    secret = "whsec_unit_test_secret"
    srv = create_server("127.0.0.1", 0, tmp_path / "meter.db", webhook_secret=secret)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        invoices_20 = [
            {
                "id": f"INV-{i}",
                "vendor": f"Vendor {i}",
                "total_usd": "125.50",
                "line_items": [{"qty": 2, "unit_price_usd": "62.75"}],
            }
            for i in range(20)
        ]

        # 1. MCP initialize & tools/list
        st_init, res_init = _post_json(
            f"http://127.0.0.1:{port}/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        )
        assert st_init == 200
        assert res_init["result"]["protocolVersion"] == "2025-11-25"

        st_tools, res_tools = _post_json(
            f"http://127.0.0.1:{port}/mcp",
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert st_tools == 200
        assert res_tools["result"]["tools"][0]["name"] == "verify_invoice_batch"

        # 2. First 20 invoices succeed via MCP tools/call
        st_call1, res_call1 = _post_json(
            f"http://127.0.0.1:{port}/mcp",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "verify_invoice_batch", "arguments": {"invoices": invoices_20}},
            },
            headers={"X-API-Key": "key-alpha"},
        )
        assert st_call1 == 200
        sc1 = res_call1["result"]["structuredContent"]
        assert sc1["audit"]["clean"] is True
        assert sc1["audit"]["total_micro_usd"] == "2510000000"
        assert sc1["meter"]["docs_used"] == 20

        # 3. 21st invoice triggers HTTP 402 Payment Required on both /mcp and /v1/verify
        st_call2, res_call2 = _post_json(
            f"http://127.0.0.1:{port}/mcp",
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "verify_invoice_batch", "arguments": {"invoices": [invoices_20[0]]}},
            },
            headers={"X-API-Key": "key-alpha"},
        )
        assert st_call2 == 402
        assert res_call2["error"]["code"] == -32002

        st_rest_402, body_402 = _post_json(
            f"http://127.0.0.1:{port}/v1/verify",
            {"invoices": [invoices_20[0]]},
            headers={"X-API-Key": "key-alpha"},
        )
        assert st_rest_402 == 402
        assert "$29.00/mo" in body_402["upgrade_plans"]["monthly_subscription"]

        # 4. Upgrade via signed Stripe HMAC webhook
        wh_payload = json.dumps({"api_key": "key-alpha", "tier": "pro_monthly", "customer_id": "cus_demo"}).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), wh_payload, hashlib.sha256).hexdigest()
        req_wh = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/webhooks/stripe",
            method="POST",
            headers={"Content-Type": "application/json", "X-Stripe-Signature": sig},
            data=wh_payload,
        )
        with urllib.request.urlopen(req_wh, timeout=5) as rw:
            assert rw.status == 200

        # 5. Upgraded key now succeeds via REST and MCP
        st_rest_ok, rest_ok = _post_json(
            f"http://127.0.0.1:{port}/v1/verify",
            {"invoices": [invoices_20[0]]},
            headers={"X-API-Key": "key-alpha"},
        )
        assert st_rest_ok == 200
        assert rest_ok["meter"]["tier"] == "pro_monthly"
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_json_and_csv_exit_codes(tmp_path: Path) -> None:
    clean_json = tmp_path / "clean.json"
    clean_json.write_text(
        json.dumps([{"id": "A1", "vendor": "North", "total_usd": "10.00", "line_items": [{"qty": 2, "unit_price_usd": "5.00"}]}]),
        encoding="utf-8",
    )
    out_report = tmp_path / "report.json"
    assert run_cli(clean_json, out_report) == 0
    assert json.loads(out_report.read_text(encoding="utf-8"))["clean"] is True

    drift_csv = tmp_path / "drift.csv"
    drift_csv.write_text("id,vendor,total_usd,expected_usd\nB1,South,19.99,20.00\n", encoding="utf-8")
    assert run_cli(drift_csv) == 2
