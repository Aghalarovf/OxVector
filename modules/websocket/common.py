import base64
import binascii
import hashlib
import re
from urllib.parse import urlparse

TOKEN_PARAM_RE = re.compile(r"token|jwt|auth|session|sid|key|apikey|api_key", re.IGNORECASE)
JS_WS_RE = re.compile(r"""new\s+WebSocket\s*\(\s*[`"']([^`"']+)[`"']""")
TWO_PART_TLDS = ("co", "com", "org", "net", "gov", "edu", "ac")

# RFC 6455 section 1.3
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

STANDARD_WS_HEADERS = frozenset({
    "sec-websocket-key",
    "sec-websocket-accept",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
})
# Hixie / hybi-draft era headers: obsolete protocol versions
OBSOLETE_WS_HEADERS = frozenset({
    "sec-websocket-key1",
    "sec-websocket-key2",
    "sec-websocket-draft",
    "websocket-origin",
    "websocket-location",
    "websocket-protocol",
})

_CSRF_NAME_RE = re.compile(r"csrf|xsrf|authenticity_token|_token|nonce", re.IGNORECASE)
try:  # the csrf module is optional for this module to work
    from modules.csrf.common import has_token_name as csrf_token_name
except ImportError:
    def csrf_token_name(name: str) -> bool:
        return bool(_CSRF_NAME_RE.search(name or ""))


def host_only(value: str) -> str:
    try:
        p = urlparse(value if "://" in value else "//" + value)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def site_of(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    if parts[-2] in TWO_PART_TLDS and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def split_tokens(value) -> list:
    """'a, b ,c' -> ['a', 'b', 'c'] (original case kept)."""
    if not isinstance(value, str):
        return []
    return [t.strip() for t in value.split(",") if t.strip()]


def upgrade_tokens(headers) -> list:
    """Protocol names from an Upgrade header, lowercased, version suffix removed."""
    raw = (headers or {}).get("upgrade", "")
    return [t.lower().split("/")[0] for t in split_tokens(raw)]


def connection_has_upgrade(headers) -> bool:
    return "upgrade" in [t.lower() for t in split_tokens((headers or {}).get("connection", ""))]


def is_switching_protocols_status(status) -> bool:
    """True for any 1xx (10x-19x) status code, as used by WebSocket upgrades."""
    try:
        status = int(status or 0)
    except (TypeError, ValueError):
        return False
    return 100 <= status < 200


def has_websocket_handshake_headers(headers) -> bool:
    """True when Upgrade: websocket, Connection: Upgrade and Sec-WebSocket-Accept are all present."""
    headers = headers or {}
    return (
        "websocket" in upgrade_tokens(headers)
        and connection_has_upgrade(headers)
        and bool(headers.get("sec-websocket-accept"))
    )


def ws_header_names(headers) -> list:
    """Every header whose name mentions websocket (standard, obsolete and custom ones)."""
    return sorted(k for k in (headers or {}) if "websocket" in str(k).lower())


ALL_WS_HEADER_NAMES = STANDARD_WS_HEADERS | OBSOLETE_WS_HEADERS

# Headers that are not WebSocket-specific by name, but whose value signals a
# WebSocket exchange when present with the right content.
WS_SIGNAL_HEADER_NAMES = frozenset({
    "upgrade",
    "connection",
    "origin",
    "sec-fetch-dest",
})


def is_sec_fetch_websocket(headers) -> bool:
    """Modern browsers (Chrome, Firefox) send Sec-Fetch-Dest: websocket on the handshake request."""
    value = (headers or {}).get("sec-fetch-dest", "")
    return str(value).strip().lower() == "websocket"


def websocket_signal_headers(headers) -> dict:
    """Every header on this side (name -> value) that is a signal of WebSocket usage:
    the standard and obsolete Sec-WebSocket-* headers, Upgrade: websocket, Connection:
    Upgrade, Origin, Sec-Fetch-Dest: websocket, and any other custom header whose name
    mentions websocket."""
    headers = headers or {}
    signals = {}
    for name, value in headers.items():
        key = str(name).lower()
        if key in ALL_WS_HEADER_NAMES or "websocket" in key:
            signals[key] = value
        elif key == "upgrade" and "websocket" in upgrade_tokens(headers):
            signals[key] = value
        elif key == "connection" and connection_has_upgrade(headers):
            signals[key] = value
        elif key == "origin":
            signals[key] = value
        elif key == "sec-fetch-dest" and is_sec_fetch_websocket(headers):
            signals[key] = value
    return signals


def handshake_outcome(status) -> str:
    """accepted = 101, informational = other 1xx, rejected = 2xx-5xx, unknown = no status."""
    try:
        status = int(status or 0)
    except (TypeError, ValueError):
        return "unknown"
    if status == 101:
        return "accepted"
    if 100 <= status < 200:
        return "informational"
    if status >= 200:
        return "rejected"
    return "unknown"


def expected_accept(key: str) -> str:
    digest = hashlib.sha1((key.strip() + WS_GUID).encode("ascii", "ignore")).digest()
    return base64.b64encode(digest).decode("ascii")


def valid_key(key: str) -> bool:
    """Sec-WebSocket-Key must be the base64 form of exactly 16 random bytes."""
    try:
        return len(base64.b64decode((key or "").strip(), validate=True)) == 16
    except (binascii.Error, ValueError):
        return False


def _scheme(url: str) -> str:
    try:
        return urlparse(url).scheme.lower()
    except Exception:
        return ""


def url_scheme_is_websocket(url: str) -> bool:
    return _scheme(url) in ("ws", "wss")


def is_websocket_exchange(record) -> bool:
    """WebSocket signal on either side of the exchange: request or response."""
    req_h = record.request.headers or {}
    resp_h = record.response.headers or {}
    if "websocket" in upgrade_tokens(req_h) or "websocket" in upgrade_tokens(resp_h):
        return True
    if ws_header_names(req_h) or ws_header_names(resp_h):
        return True
    return _scheme(record.request.url) in ("ws", "wss")


def is_handshake(record) -> bool:
    """Any protocol-switch exchange: WebSocket, any other Upgrade, or a bare 101."""
    if is_websocket_exchange(record):
        return True
    if upgrade_tokens(record.request.headers) or upgrade_tokens(record.response.headers):
        return True
    return record.response.status == 101

CANONICAL_HEADER_NAMES = {
    "upgrade": "Upgrade",
    "connection": "Connection",
    "sec-websocket-key": "Sec-WebSocket-Key",
    "sec-websocket-accept": "Sec-WebSocket-Accept",
    "sec-websocket-version": "Sec-WebSocket-Version",
    "sec-websocket-protocol": "Sec-WebSocket-Protocol",
    "sec-websocket-extensions": "Sec-WebSocket-Extensions",
    "sec-websocket-key1": "Sec-WebSocket-Key1",
    "sec-websocket-key2": "Sec-WebSocket-Key2",
    "sec-websocket-draft": "Sec-WebSocket-Draft",
    "websocket-origin": "WebSocket-Origin",
    "websocket-location": "WebSocket-Location",
    "websocket-protocol": "WebSocket-Protocol",
}


def _header_label(name: str) -> str:
    return CANONICAL_HEADER_NAMES.get(str(name).lower(), str(name))


def _header_value(value, limit: int = 80) -> str:
    text = str(value).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def _side_reasons(headers, source: str) -> list:
    headers = headers or {}
    reasons = []
    if "websocket" in upgrade_tokens(headers):
        reasons.append({"source": source, "detail": f"Upgrade: {_header_value(headers.get('upgrade', ''))}"})
        if connection_has_upgrade(headers):
            reasons.append({"source": source, "detail": f"Connection: {_header_value(headers.get('connection', ''))}"})
    for name in ws_header_names(headers):
        reasons.append({"source": source, "detail": f"{_header_label(name)}: {_header_value(headers[name])}"})
    return reasons


def websocket_reasons(record) -> list:
    reasons = _side_reasons(record.request.headers, "Request header")
    reasons.extend(_side_reasons(record.response.headers, "Response header"))
    scheme = _scheme(record.request.url)
    if scheme in ("ws", "wss"):
        reasons.append({"source": "URL scheme", "detail": f"{scheme}://"})
    return reasons