from typing import List
from urllib.parse import urlparse, parse_qs
from core.models import HttpRecord, Finding
from core.http_utils import url_path
from modules.websocket.common import (
    OBSOLETE_WS_HEADERS,
    STANDARD_WS_HEADERS,
    TOKEN_PARAM_RE,
    connection_has_upgrade,
    csrf_token_name,
    expected_accept,
    handshake_outcome,
    has_websocket_handshake_headers,
    host_only,
    is_handshake,
    is_sec_fetch_websocket,
    is_switching_protocols_status,
    is_websocket_exchange,
    site_of,
    split_tokens,
    upgrade_tokens,
    url_scheme_is_websocket,
    valid_key,
    websocket_reasons,
    websocket_signal_headers,
    ws_header_names,
)

_CRED_WORDS = ("token", "jwt", "bearer", "auth", "apikey", "api_key", "session")


def _clip(value, n=80) -> str:
    value = str(value)
    return value if len(value) <= n else value[:n] + "..."


def _looks_like_credential(entry: str) -> bool:
    low = entry.lower()
    if any(w in low for w in _CRED_WORDS):
        return True
    parts = entry.split(".")
    return len(parts) == 3 and entry.startswith("eyJ")


class WebsocketHandshakeAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        if not is_handshake(record):
            return []

        req = record.request
        resp = record.response
        req_h = req.headers or {}
        resp_h = resp.headers or {}
        status = resp.status or 0
        outcome = handshake_outcome(status)
        is_ws = is_websocket_exchange(record)
        reasons = websocket_reasons(record) if is_ws else []

        findings: List[Finding] = []

        def add(sev, title, evidence, hint, confidence="candidate", **extra_fields):
            details = {"handshake_status": status, "handshake_outcome": outcome}
            if reasons:
                details["websocket_reasons"] = [dict(r) for r in reasons]
            details.update(extra_fields)
            findings.append(Finding(
                module="websocket",
                severity=sev,
                title=f"WebSocket: {title}",
                location=req.url,
                evidence=evidence,
                vector_hint=hint,
                confidence=confidence,
                extra=details,
            ))

        self._upgrade_checks(add, req_h, resp_h, status, outcome, is_ws)
        self._connection_established_check(add, resp_h, status)
        if not is_ws:
            return findings

        self._status_checks(add, resp_h, status, outcome)
        self._request_checks(add, req, req_h, outcome)
        self._response_checks(add, req_h, resp_h, status, outcome)
        self._subprotocol_checks(add, req_h, resp_h, outcome)
        self._extension_checks(add, resp_h)
        self._header_inventory(add, findings, req, req_h, resp_h, status)
        return findings

    # ---- Upgrade header (any protocol) -------------------------------------

    def _upgrade_checks(self, add, req_h, resp_h, status, outcome, is_ws):
        req_up = upgrade_tokens(req_h)
        resp_up = upgrade_tokens(resp_h)
        other = sorted({t for t in req_up + resp_up if t != "websocket"})

        if other:
            if "h2c" in other and outcome == "accepted":
                add("medium", "h2c Upgrade Accepted",
                    f"Upgrade: h2c answered with status {status}",
                    "Cleartext HTTP/2 upgrade through a proxy can bypass proxy-level access controls (h2c smuggling); confirm the proxy strips Upgrade: h2c")
            else:
                add("info", "Non-WebSocket Upgrade Header",
                    f"Upgrade value(s): {', '.join(other)} (status {status})",
                    "Protocol upgrade other than WebSocket; check whether the server and any front proxy handle it consistently")

        if status == 101 and not req_up and not resp_up and not is_ws:
            add("info", "101 Response Without Upgrade Header",
                "Status 101 Switching Protocols but neither side carries an Upgrade header",
                "Protocol switch is not declared; capture may have stripped hop-by-hop headers, or the server is non-compliant")

    # ---- 1xx status + WebSocket headers -> connection established -----------

    def _connection_established_check(self, add, resp_h, status):
        if not is_switching_protocols_status(status):
            return
        if not has_websocket_handshake_headers(resp_h):
            return
        add("info", "Connection Established",
            f"Status {status} with Upgrade: {resp_h.get('upgrade', '')}, "
            f"Connection: {resp_h.get('connection', '')}, "
            f"Sec-WebSocket-Accept: {_clip(resp_h.get('sec-websocket-accept', ''), 40)}",
            "Response status is 1xx and carries Upgrade: websocket, Connection: Upgrade and "
            "Sec-WebSocket-Accept together, confirming a successful WebSocket connection",
            confidence="confirmed", websocket_detected=True)

    # ---- status code (1xx / rejected) ---------------------------------------

    def _status_checks(self, add, resp_h, status, outcome):
        if outcome == "informational":
            add("info", f"Informational Status {status} in Handshake Exchange",
                f"Handshake exchange answered with 1xx status {status} instead of 101",
                "100/102/103 are interim responses; check whether a final 101 follows or an intermediary is interfering")
        elif outcome == "rejected":
            if status == 426:
                reason = "426 Upgrade Required"
            elif status in (401, 403):
                reason = f"{status}: handshake refused by access control"
            elif 200 <= status < 300:
                reason = f"{status}: server ignored the Upgrade and answered normally"
            elif 300 <= status < 400:
                reason = f"{status}: handshake answered with a redirect"
            elif status == 400:
                reason = "400: malformed or unsupported handshake"
            else:
                reason = f"{status}: handshake did not complete"
            versions = resp_h.get("sec-websocket-version")
            extra = f"; server advertises Sec-WebSocket-Version: {_clip(versions)}" if versions else ""
            add("info", f"Handshake Not Completed (status {status})",
                reason + extra,
                "Handshake was refused; compare with a request using a valid Origin and credentials to see which check rejected it")

    # ---- request side -------------------------------------------------------

    def _request_checks(self, add, req, req_h, outcome):
        parsed = urlparse(req.url)
        scheme = parsed.scheme.lower()
        path = url_path(req.url)
        accepted = outcome == "accepted"
        authenticated_outcome = outcome in ("accepted", "unknown")

        if scheme in ("ws", "http"):
            add("medium", "Unencrypted WebSocket Connection",
                "Handshake over ws:// (no TLS)",
                "Traffic and any session data can be read or modified on the network; require wss://")

        origin = req_h.get("origin", "")
        host = host_only(req.url)
        if origin and host and accepted:
            if origin.strip().lower() == "null":
                add("medium", "Handshake Accepted With Origin: null",
                    f"Origin 'null' accepted by {host} (status 101)",
                    "Sandboxed iframes and local files send Origin null; accepting it weakens cross-site WebSocket hijacking defense",
                    confidence="likely")
            else:
                origin_host = host_only(origin)
                if origin_host and site_of(origin_host) != site_of(host):
                    add("high", "Cross-Origin Handshake Accepted",
                        f"Origin {origin_host} accepted by {host} (status 101)",
                        "Server completed the handshake for a foreign Origin — cross-site WebSocket hijacking is likely possible",
                        confidence="likely")

        has_cookie = bool(req_h.get("cookie"))
        has_auth_header = bool(req_h.get("authorization"))
        query = parse_qs(parsed.query, keep_blank_values=True)
        token_in_url = [k for k in query if TOKEN_PARAM_RE.search(k)]
        csrf_like = any(csrf_token_name(k) for k in query)

        if token_in_url:
            add("medium", "Credential in WebSocket URL",
                f"Query parameter(s) in handshake URL: {', '.join(sorted(token_in_url))}",
                "Tokens in WebSocket URLs end up in logs, history and proxies")

        if authenticated_outcome and has_cookie and not has_auth_header and not token_in_url and not csrf_like:
            origin_host = host_only(origin) if origin else ""
            same_site = bool(origin_host and host and site_of(origin_host) == site_of(host))
            if same_site:
                add("info", "Cookie-Authenticated Handshake (same-site Origin)",
                    f"Handshake {path} uses cookies; Origin {origin_host} matches {host}",
                    "Normal browser traffic. Cross-site WebSocket hijacking is only possible if the server does not validate Origin; replay with a foreign Origin to confirm")
            else:
                add("medium", "Cookie-Only Handshake Authentication",
                    f"Handshake {path} authenticates with cookies and has no token or CSRF-style parameter",
                    "Test cross-site WebSocket hijacking: connect from a page on another origin and check whether the server validates Origin")

        if authenticated_outcome and not origin and has_cookie:
            add("low", "Handshake Without Origin Header",
                f"Handshake {path} sent without Origin",
                "Origin is the only browser-enforced signal for CSWSH defense; confirm the server rejects missing and foreign values")

        versions = [v.strip() for v in split_tokens(req_h.get("sec-websocket-version", ""))]
        if versions and "13" not in versions:
            add("medium" if accepted else "info", "Deprecated Sec-WebSocket-Version",
                f"Sec-WebSocket-Version: {_clip(', '.join(versions))}"
                + (" accepted by server" if accepted else ""),
                "Only version 13 (RFC 6455) is current; older hybi versions lack protections such as masking guarantees")

        if accepted and "websocket" in upgrade_tokens(req_h):
            key = req_h.get("sec-websocket-key")
            if key is None:
                add("low", "Handshake Accepted Without Sec-WebSocket-Key",
                    "Upgrade: websocket request has no Sec-WebSocket-Key but got status 101",
                    "A compliant server must reject it; the server (or an intermediary) does not validate the handshake")
            elif not valid_key(key):
                add("low", "Handshake Accepted With Invalid Sec-WebSocket-Key",
                    f"Sec-WebSocket-Key {_clip(key, 40)!r} is not base64 of 16 bytes, status 101",
                    "Server does not validate the key; try malformed handshakes against the endpoint")

    # ---- response side ------------------------------------------------------

    def _response_checks(self, add, req_h, resp_h, status, outcome):
        if outcome != "accepted":
            return

        problems = []
        if "websocket" not in upgrade_tokens(resp_h):
            problems.append("Upgrade: websocket missing")
        if not connection_has_upgrade(resp_h):
            problems.append("Connection: Upgrade missing")
        accept = resp_h.get("sec-websocket-accept")
        if not accept:
            problems.append("Sec-WebSocket-Accept missing")
        if problems:
            add("low", "Non-Compliant 101 Response",
                "; ".join(problems),
                "RFC 6455 requires all three on a successful handshake; capture tools sometimes strip hop-by-hop headers, so verify on the wire")

        key = req_h.get("sec-websocket-key")
        if accept and key and valid_key(key):
            expected = expected_accept(key)
            if accept.strip() != expected:
                add("low", "Sec-WebSocket-Accept Does Not Match Request Key",
                    f"Got {_clip(accept, 40)}, expected {expected}",
                    "Response does not belong to this request or the server computes the accept value incorrectly; check for a proxy or caching layer in the path")

    def _subprotocol_checks(self, add, req_h, resp_h, outcome):
        requested = split_tokens(req_h.get("sec-websocket-protocol", ""))
        selected = (resp_h.get("sec-websocket-protocol") or "").strip()

        creds = [p for p in requested if _looks_like_credential(p)]
        if creds:
            add("medium", "Credential in Sec-WebSocket-Protocol Header",
                f"Subprotocol entry looks like a credential: {_clip(creds[0], 40)}",
                "Passing tokens through the subprotocol header is a workaround for missing header support; it is logged by proxies and echoed back by the server")

        if outcome == "accepted" and selected and selected not in requested:
            add("low", "Server Selected Unrequested Subprotocol",
                f"Response Sec-WebSocket-Protocol: {_clip(selected)}; request offered: {_clip(', '.join(requested)) or 'none'}",
                "Clients must fail the connection in this case; indicates a non-compliant server or intermediary")

    def _extension_checks(self, add, resp_h):
        ext = (resp_h.get("sec-websocket-extensions") or "").lower()
        if "permessage-deflate" in ext:
            add("info", "Compression Negotiated (permessage-deflate)",
                f"Sec-WebSocket-Extensions: {_clip(ext)}",
                "Compressed frames mixing secrets with attacker-controlled data allow length-based side channels (CRIME/BREACH style)")

    # ---- all WebSocket-related headers and markers ---------------------------

    def _header_inventory(self, add, findings, req, req_h, resp_h, status):
        names = set(ws_header_names(req_h)) | set(ws_header_names(resp_h))

        obsolete = sorted(names & OBSOLETE_WS_HEADERS)
        if obsolete:
            add("medium", "Obsolete WebSocket Protocol Headers",
                f"Draft-era header(s): {', '.join(obsolete)}",
                "Hixie/hybi draft handshakes are insecure and unmasked; the endpoint should accept only RFC 6455")

        custom = sorted(n for n in names if n not in STANDARD_WS_HEADERS and n not in OBSOLETE_WS_HEADERS)
        if custom:
            add("info", "Non-Standard WebSocket Header",
                f"Header(s): {', '.join(custom)}",
                "Custom headers often carry auth or routing decisions; test whether the server trusts them")

        if is_sec_fetch_websocket(req_h):
            add("info", "Sec-Fetch-Dest: websocket Present",
                f"Request Sec-Fetch-Dest: {req_h.get('sec-fetch-dest', '')}",
                "Modern browsers mark the WebSocket handshake request with Sec-Fetch-Dest: websocket; "
                "a server-side check on this header can reject handshakes made outside the browser",
                confidence="confirmed")

        req_ws = {k: _clip(v, 120) for k, v in websocket_signal_headers(req_h).items()}
        resp_ws = {k: _clip(v, 120) for k, v in websocket_signal_headers(resp_h).items()}
        scheme_ws = url_scheme_is_websocket(req.url)

        evidence = (
            f"Request: {', '.join(sorted(req_ws)) or 'none'} | "
            f"Response ({status}): {', '.join(sorted(resp_ws)) or 'none'}"
        )
        if scheme_ws:
            evidence += " | URL scheme: ws/wss"

        add("info", "WebSocket Headers Observed",
            evidence,
            "Inventory of every header and marker (request, response, URL scheme) that signals "
            "WebSocket usage; see finding extra for the full values",
            confidence="confirmed", websocket_detected=True)
        findings[-1].extra.update({
            "request_ws_headers": req_ws,
            "response_ws_headers": resp_ws,
            "url_scheme_is_websocket": scheme_ws,
        })