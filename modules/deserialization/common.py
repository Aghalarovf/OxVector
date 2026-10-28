import base64
import binascii
import gzip
import re
from urllib.parse import unquote

B64_RE = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")
PHP_OBJECT_RE = re.compile(r'^O:\d+:"[\w\\]+":\d+:\{')
PHP_ARRAY_RE = re.compile(r"^a:\d+:\{")
NODE_SERIALIZE_MARK = "_$$ND_FUNC$$_"
XML_DECODER_RE = re.compile(r"<java\s+version=|<object\s+class=\"java\.", re.IGNORECASE)


def try_base64(value: str):
    v = value.strip()
    if len(v) < 8 or not B64_RE.match(v):
        return None
    v = v.replace("-", "+").replace("_", "/")
    v += "=" * (-len(v) % 4)
    try:
        return base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return None


def try_hex(value: str):
    v = value.strip()
    if len(v) < 8 or len(v) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", v):
        return None
    try:
        return bytes.fromhex(v)
    except ValueError:
        return None


def classify_bytes(data: bytes):
    if not data:
        return None
    if data[:2] == b"\x1f\x8b":
        try:
            inner = gzip.decompress(data)
        except Exception:
            return None
        return classify_bytes(inner)
    if data[:4] == b"\xac\xed\x00\x05":
        return "Java serialized object"
    if data[:9] == b"\x00\x01\x00\x00\x00\xff\xff\xff\xff":
        return ".NET BinaryFormatter payload"
    if len(data) > 3 and data[0] == 0x80 and data[1] in (2, 3, 4, 5) and data[-1] == 0x2E:
        return "Python pickle"
    if data[:2] == b"\x04\x08":
        return "Ruby Marshal data"
    return None


def classify_text(text: str):
    t = text.strip()
    if PHP_OBJECT_RE.match(t):
        return "PHP serialized object"
    if PHP_ARRAY_RE.match(t):
        return "PHP serialized array"
    if NODE_SERIALIZE_MARK in t:
        return "node-serialize function payload"
    if XML_DECODER_RE.search(t[:2048]):
        return "Java XMLDecoder XML"
    return None


def classify_value(value):
    if not isinstance(value, str) or len(value) < 8:
        return None
    candidates = [value]
    decoded = unquote(value)
    if decoded != value:
        candidates.append(decoded)
    for cand in candidates:
        kind = classify_text(cand)
        if kind:
            return kind
        data = try_hex(cand) or try_base64(cand)
        if data:
            kind = classify_bytes(data)
            if kind:
                return kind
    return None


def parse_cookie_header(raw: str):
    out = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def preview(value: str, n: int = 32) -> str:
    v = value if len(value) <= n else value[:n] + "..."
    return v
