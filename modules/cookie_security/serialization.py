import base64
import binascii
import gzip
import re
from typing import List, Optional, Tuple
from urllib.parse import unquote
from core.models import HttpRecord, Finding
from core.http_utils import parse_set_cookies, parse_cookie_header

B64_RE = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")
FLASK_RE = re.compile(r"^\.?[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{5,8}\.[A-Za-z0-9_\-]{27}$")
PHP_RE = re.compile(r'(^|[;{])(O:\d+:"[^"]+":\d+:\{|a:\d+:\{|s:\d+:"|i:\d+;|b:[01];)')
JSON_TYPE_RE = re.compile(r'"(@type|\$type|@class|_type|__type)"\s*:\s*"[^"]+"')

HIGH = "high"
MEDIUM = "medium"
LOW = "low"


def _decode_candidates(value: str) -> List[bytes]:
    candidates = []
    text = unquote(value)
    candidates.append(text.encode("utf-8", errors="ignore"))
    if len(text) >= 8 and B64_RE.fullmatch(text):
        normalized = text.replace("-", "+").replace("_", "/")
        normalized += "=" * (-len(normalized) % 4)
        try:
            candidates.append(base64.b64decode(normalized, validate=True))
        except (binascii.Error, ValueError):
            pass
    if len(text) >= 8 and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        try:
            candidates.append(bytes.fromhex(text))
        except ValueError:
            pass
    return candidates


def _classify(value: str) -> Optional[Tuple[str, str, str]]:
    text = unquote(value)
    if FLASK_RE.fullmatch(text):
        return (LOW, "Signed Serializer Cookie (Flask / itsdangerous Format)",
                "Value follows the payload.timestamp.signature layout; test for a weak or default secret key")

    for data in _decode_candidates(value):
        if data[:4] == b"\xac\xed\x00\x05":
            return (HIGH, "Java Serialized Object",
                    "Stream starts with the Java serialization magic bytes; test for insecure deserialization gadget chains")
        if data[:2] == b"\x1f\x8b":
            try:
                inner = gzip.decompress(data)[:8]
            except Exception:
                inner = b""
            if inner[:4] == b"\xac\xed\x00\x05":
                return (HIGH, "Compressed Java Serialized Object",
                        "Gzip-compressed Java serialization stream; decompress and test for deserialization gadget chains")
        if data[:2] in (b"\x80\x03", b"\x80\x04", b"\x80\x05") and len(data) > 4:
            return (HIGH, "Python Pickle Data",
                    "Pickle protocol header detected; unpickling attacker-controlled data allows code execution")
        if data[:5] == b"\x00\x01\x00\x00\x00" and b"\xff\xff\xff\xff" in data[:12]:
            return (HIGH, ".NET BinaryFormatter Data",
                    "BinaryFormatter header detected; deserialization of untrusted data can lead to code execution")
        if data[:2] == b"\x04\x08":
            return (MEDIUM, "Ruby Marshal Data",
                    "Marshal header detected; loading attacker-controlled data can lead to object injection")
        if data[:2] == b"\xff\x01" and len(data) > 8:
            return (MEDIUM, ".NET ViewState / LosFormatter Data",
                    "ViewState-style header detected; check MAC validation and machine key strength")

        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "_$$ND_FUNC$$_" in decoded:
            return (HIGH, "Node.js node-serialize Payload Marker",
                    "node-serialize function marker detected; unserialize of attacker data allows code execution")
        if decoded.startswith(("O:", "a:", "s:", "i:", "b:")) and PHP_RE.search(decoded):
            return (MEDIUM, "PHP Serialized Data",
                    "PHP serialize() format detected; test for object injection and magic method gadget chains")
        if JSON_TYPE_RE.search(decoded):
            return (MEDIUM, "JSON With Embedded Type Information",
                    "Type discriminator found in JSON; polymorphic deserialization may allow arbitrary class instantiation")
    return None


class CookieSecuritySerializationAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        url = record.request.url

        sources = []
        for cookie in parse_set_cookies((record.response.headers or {}).get("set-cookie", "")):
            sources.append(("Set-Cookie", cookie["name"], cookie["value"]))
        for name, value in parse_cookie_header((record.request.headers or {}).get("cookie", "")).items():
            sources.append(("Cookie", name, value))

        for origin, name, value in sources:
            if not value or len(value) < 8:
                continue
            result = _classify(value)
            if not result:
                continue
            severity, kind, hint = result
            findings.append(Finding(
                module="cookie_security",
                severity=severity,
                title=f"Cookie Security: {kind}",
                location=url,
                evidence=f"{origin} {name} contains {kind.lower()} ({len(value)} characters)",
                vector_hint=hint,
                confidence="candidate",
                extra={"cookie": name, "origin": origin},
            ))
        return findings