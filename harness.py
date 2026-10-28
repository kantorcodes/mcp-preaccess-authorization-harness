"""Deterministic, synthetic pre-access authorization harness.

Not a full MCP server, OAuth authorization server, or proof of industrial safety.
Only loopback HTTP and mock data; Python standard library only.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

PROTOCOL = "2026-07-28"
ISSUER = "https://synthetic-issuer.invalid"
AUDIENCE = "http://127.0.0.1/mcp"
PRINCIPAL = "test-target-service"  # target-only credential, not the caller's MCP token
TARGET_KEY = secrets.token_urlsafe(32)


@dataclass(frozen=True)
class Grant:
    issuer: str = ISSUER
    audience: str = AUDIENCE
    subject: str = "tester"
    site: str = "A"
    operations: tuple[str, ...] = ("read", "write")
    expires_at: float = 0.0
    revoked: bool = False


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.records = {"A": 10, "B": 20}
        self.target_events: list[dict] = []
        self.gateway_events: list[dict] = []
        self.grants: dict[str, Grant] = {}
        self.policy_available = True
        self.permissive = False
        self.target_url = ""

    def issue(self, **overrides):
        token = secrets.token_urlsafe(24)  # opaque token, validated by synthetic issuer registry
        grant = Grant(**{"expires_at": time.time() + 3600, **overrides})
        self.grants[token] = grant
        return token

    def reset(self):
        with self.lock:
            self.records = {"A": 10, "B": 20}
            self.target_events.clear()
            self.gateway_events.clear()
            self.grants.clear()
            self.permissive = False
            self.policy_available = True


S = State()


class Handler(BaseHTTPRequestHandler):
    server_version = "SyntheticMCPAuthLab/0.1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def reply(self, status, data):
        body = json.dumps(data, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 20000:
            return self.reply(413, {"error": "oversized"})
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeError):
            return self.reply(400, {"error": "invalid JSON"})
        if self.path == "/target":
            return self.target(data)
        if self.path == "/mcp":
            return self.gateway(data)
        return self.reply(404, {"error": "not found"})

    def target(self, data):
        if self.headers.get("X-Target-Key") != TARGET_KEY:
            return self.reply(403, {"error": "target service credential required"})
        site = data.get("site")
        op = data.get("op")
        req_id = data.get("request_id")
        if site not in ("A", "B") or op not in ("read", "write"):
            return self.reply(400, {"error": "invalid target request"})
        with S.lock:
            before = S.records[site]
            if op == "write":
                value = data.get("value")
                if type(value) is not int:
                    return self.reply(400, {"error": "invalid value"})
                S.records[site] = value
            after = S.records[site]
            S.target_events.append({"request_id": req_id, "site": site,
                                    "operation": op, "before": before,
                                    "after": after, "principal": PRINCIPAL})
        return self.reply(200, {"value": after, "request_id": req_id})

    def gateway(self, data):
        req_id = str(data.get("id", "?"))
        headers = self.headers
        meta = data.get("params", {}).get("_meta", {})
        method = data.get("method")
        tool = data.get("params", {}).get("name")

        def reject(status, code, message):
            with S.lock:
                S.gateway_events.append({"request_id": req_id, "decision": "deny", "reason": message})
            return self.reply(status, {"jsonrpc": "2.0", "id": data.get("id"),
                                       "error": {"code": code, "message": message}})

        # This fixture models the subset of protocol headers needed for the experiment.
        # It does not claim full conformance to the 2026 MCP specification.
        if not all([headers.get("MCP-Protocol-Version"), headers.get("Mcp-Method"),
                    headers.get("Mcp-Name")]):
            return reject(400, -32020, "missing required mirrored header")
        if (headers.get("MCP-Protocol-Version") != PROTOCOL or
            headers.get("Mcp-Method") != method or headers.get("Mcp-Name") != tool):
            return reject(400, -32020, "header/body mismatch")
        if meta.get("io.modelcontextprotocol/protocolVersion") != PROTOCOL or \
           "io.modelcontextprotocol/clientCapabilities" not in meta:
            return reject(400, -32602, "invalid request metadata")
        if method != "tools/call" or tool not in ("read_record", "write_record"):
            return reject(404, -32601, "unknown tool")

        raw_token = headers.get("Authorization", "")
        if not raw_token.startswith("Bearer "):
            return reject(401, -32000, "missing bearer credential")
        token = raw_token[7:]
        grant = S.grants.get(token)
        if (grant is None or grant.revoked or grant.expires_at <= time.time() or
            grant.issuer != ISSUER or grant.audience != AUDIENCE):
            return reject(401, -32000, "invalid issuer, audience, expiry or token")
        if not S.policy_available:
            return reject(503, -32000, "policy unavailable: fail closed")

        op = "read" if tool == "read_record" else "write"
        args = data.get("params", {}).get("arguments", {})
        site = args.get("site")
        val = args.get("value")
        if site not in ("A", "B"):
            return reject(403, -32000, "invalid site")
        if op not in grant.operations:
            return reject(403, -32000, "operation outside grant")
        if site != grant.site and not S.permissive:
            return reject(403, -32000, "site outside grant")
        if op == "write" and (type(val) is not int or not 0 <= val <= 100):
            return reject(403, -32000, "parameter outside allowed range")
        # Synthetic downstream service identity is separate from MCP token.
        payload = {"request_id": req_id, "site": site, "op": op, "value": val}
        status, target = post(S.target_url, payload, {"X-Target-Key": TARGET_KEY})
        with S.lock:
            S.gateway_events.append({"request_id": req_id, "decision": "allow", "site": site,
                                     "operation": op, "target_status": status})
        if status != 200:
            return reject(502, -32000, "downstream operation failed")
        return self.reply(200, {"jsonrpc": "2.0", "id": data.get("id"),
                                "result": {"content": [{"type": "text", "text": str(target["value"])}]}})


def post(url: str, obj: dict, extra: dict | None = None):
    headers = {"Content-Type": "application/json", **(extra or {})}
    req = Request(url, data=json.dumps(obj).encode(), headers=headers, method="POST")
    try:
        with urlopen(req, timeout=3) as resp:
            return resp.status, json.load(resp)
    except HTTPError as ex:
        return ex.code, json.load(ex)


def invoke(url: str, token: str | None, op: str, site: str, value: int = 30,
           override: dict | None = None, req_id: str = "test"):
    tool = "read_record" if op == "read" else "write_record"
    params = {"name": tool, "arguments": {"site": site, "value": value},
              "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL,
                        "io.modelcontextprotocol/clientCapabilities": {}}}
    body = {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params}
    hdr = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL,
           "Mcp-Method": "tools/call", "Mcp-Name": tool}
    if token:
        hdr["Authorization"] = "Bearer " + token
    hdr.update(override or {})
    return post(url, body, hdr)


def check_case(name, status, expected_status, before, after, expected_delta, target_event_delta, evidence):
    result = {"case": name, "status": status, "expected_status": expected_status,
              "before": before, "after": after, "expected_delta": expected_delta,
              "new_target_events": target_event_delta,
              "pass": status == expected_status and after == expected_delta[1]
              and target_event_delta == expected_delta[2]}
    evidence.append(result)
    if not result["pass"]:
        raise AssertionError(json.dumps(result))


def main():
    target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    gateway = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    target.daemon_threads = True
    gateway.daemon_threads = True
    target_url = f"http://127.0.0.1:{target.server_address[1]}/target"
    gateway_url = f"http://127.0.0.1:{gateway.server_address[1]}/mcp"
    S.target_url = target_url
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (target, gateway)]
    for t in threads:
        t.start()
    evidence = []
    cases = []
    try:
        for repeat in range(1, 4):
            S.reset()
            good = S.issue()
            read_only = S.issue(operations=("read",))
            wrong_issuer = S.issue(issuer="https://wrong.invalid")
            wrong_aud = S.issue(audience="http://wrong.invalid")
            expired = S.issue(expires_at=time.time() - 1)
            with S.lock:
                before = dict(S.records)
            # authorized read
            st, _ = invoke(gateway_url, good, "read", "A", req_id=f"r{repeat}-read")
            assert st == 200 and S.records == before and len(S.target_events) == 1
            cases.append({"repeat": repeat, "case": "authorized-read", "status": st, "pass": True})
            # authorized write
            st, _ = invoke(gateway_url, good, "write", "A", 31, req_id=f"r{repeat}-write")
            assert st == 200 and S.records["A"] == 31 and len(S.target_events) == 2
            cases.append({"repeat": repeat, "case": "authorized-write", "status": st, "pass": True})
            # deliberate policy weakness must demonstrate an actual forbidden effect
            S.permissive = True
            st, _ = invoke(gateway_url, good, "write", "B", 32, req_id=f"r{repeat}-baseline")
            assert st == 200 and S.records["B"] == 32 and len(S.target_events) == 3
            cases.append({"repeat": repeat, "case": "deliberate-permissive-baseline", "status": st, "pass": True})
            # restricted control same request, same grant, restored target initial value
            with S.lock:
                S.records["B"] = 20
            S.permissive = False
            checks = [
                ("cross-site-write", good, "write", "B", 32, 403, None),
                ("insufficient-rights", read_only, "write", "A", 32, 403, None),
                ("out-of-range", good, "write", "A", 101, 403, None),
                ("missing-credential", None, "read", "A", 30, 401, None),
                ("unknown-credential", "not-a-token", "read", "A", 30, 401, None),
                ("wrong-issuer", wrong_issuer, "read", "A", 30, 401, None),
                ("wrong-audience", wrong_aud, "read", "A", 30, 401, None),
                ("expired", expired, "read", "A", 30, 401, None),
                ("header-name-mismatch", good, "write", "A", 32, 400, {"Mcp-Name": "read_record"}),
                ("header-method-missing", good, "write", "A", 32, 400, {"Mcp-Method": ""}),
            ]
            for name, tok, op, site, val, expected, headers in checks:
                before = dict(S.records)
                num_events = len(S.target_events)
                st, _ = invoke(gateway_url, tok, op, site, val, headers, req_id=f"r{repeat}-{name}")
                assert st == expected and S.records == before and len(S.target_events) == num_events, name
                cases.append({"repeat": repeat, "case": name, "status": st, "pass": True,
                              "target_unchanged": True})
            # direct target bypass without target service credential
            before = dict(S.records)
            num_events = len(S.target_events)
            st, _ = post(target_url, {"site": "A", "op": "write", "value": 77, "request_id": "bypass"})
            assert st == 403 and S.records == before and len(S.target_events) == num_events
            cases.append({"repeat": repeat, "case": "direct-target-without-credential", "status": st, "pass": True})
            # fail closed on unavailable policy
            S.policy_available = False
            st, _ = invoke(gateway_url, good, "write", "A", 42, req_id=f"r{repeat}-policy-offline")
            assert st == 503 and S.records == before and len(S.target_events) == num_events
            cases.append({"repeat": repeat, "case": "policy-unavailable", "status": st, "pass": True})
            S.policy_available = True
            # revocation with reused HTTP client (not an MCP session)
            S.grants[good] = Grant(revoked=True, expires_at=time.time() + 3600)
            st, _ = invoke(gateway_url, good, "write", "A", 42, req_id=f"r{repeat}-revoked")
            assert st == 401 and S.records == before and len(S.target_events) == num_events
            cases.append({"repeat": repeat, "case": "revoked-grant", "status": st, "pass": True})
        # No task queues, retries or delayed jobs exist; response completes after target call.
        # Keep a small bounded settle period, not an invented 60-second observation.
        last_event_count = len(S.target_events)
        time.sleep(1)
        assert len(S.target_events) == last_event_count
        out = {"harness_version": "0.1.0", "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "runtime": {"python": __import__("sys").version.split()[0], "dependencies": "stdlib only"},
               "protocol_target": PROTOCOL,
               "scope": "synthetic deterministic HTTP boundary fixture; not a conformant MCP implementation; no industrial safety claims",
               "cases": cases, "case_total": len(cases), "all_passed": all(x["pass"] for x in cases),
               "target_log_last_repeat": S.target_events,
               "gateway_log_last_repeat": S.gateway_events,
               "no_async_queue": True, "observation_seconds": 1,
               "approval_reuse": "not applicable: no approval artifact or approval service exists",
               "limitations": ["Opaque grant registry models introspection, not a real OAuth server",
                               "Only loopback mock HTTP/JSON-RPC subset, no deployed MCP SDK interoperability",
                               "No asynchronous target tasks, retries or model/prompt injection exercised",
                               "Three repetitions are demonstrations, not reliability estimates"]}
        path = Path(__file__).with_name("evidence.json")
        path.write_text(json.dumps(out, indent=2) + "\n")
        print(json.dumps({"total": len(cases), "passed": out["all_passed"],
                          "evidence": str(path), "hash": hashlib.sha256(path.read_bytes()).hexdigest()}))
    finally:
        gateway.shutdown()
        target.shutdown()
        gateway.server_close()
        target.server_close()


if __name__ == "__main__":
    main()
