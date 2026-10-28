import base64
import binascii
import gzip
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import unquote

from modules.deserialization import signatures

B64_RE = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
PHP_OBJECT_RE = re.compile(r'^O:(\d+):"([\w\\]+)":(\d+):\{')
PHP_ARRAY_RE = re.compile(r"^a:(\d+):\{")
PHP_STRING_FIELD_RE = re.compile(r's:(\d+):"((?:[^"\\]|\\.)*)";')
NODE_SERIALIZE_MARK = "_$$ND_FUNC$$_"
XML_DECODER_RE = re.compile(r"<java\s+version=|<object\s+class=\"java\.", re.IGNORECASE)

JAVA_MAGIC = b"\xac\xed\x00\x05"
DOTNET_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
RUBY_MAGIC = b"\x04\x08"
GZIP_MAGIC = b"\x1f\x8b"

MAX_DECODE_LAYERS = 5


@dataclass
class DecodedPayload:
    original: str
    encoding_chain: List[str] = field(default_factory=list)
    decoded_text: Optional[str] = None
    decoded_bytes: Optional[bytes] = None
    signature: Optional[dict] = None
    analysis: dict = field(default_factory=dict)

    @property
    def language(self) -> Optional[str]:
        return self.signature.get("language") if self.signature else None

    @property
    def encoding_summary(self) -> str:
        return " -> ".join(self.encoding_chain) if self.encoding_chain else "none"


def _url_decode(value: str) -> Optional[str]:
    decoded = unquote(value)
    return decoded if decoded != value else None


def _base64_decode(value: str) -> Optional[bytes]:
    v = value.strip()
    if len(v) < 8 or not B64_RE.match(v):
        return None
    v = v.replace("-", "+").replace("_", "/")
    v += "=" * (-len(v) % 4)
    try:
        return base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex_decode(value: str) -> Optional[bytes]:
    v = value.strip()
    if len(v) < 8 or len(v) % 2 or not HEX_RE.match(v):
        return None
    try:
        return bytes.fromhex(v)
    except ValueError:
        return None


def _gzip_decode(data: bytes) -> Optional[bytes]:
    if data[:2] != GZIP_MAGIC:
        return None
    try:
        return gzip.decompress(data)
    except Exception:
        return None


def _as_text(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def classify_text(text: str) -> Optional[str]:
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


def classify_bytes(data: bytes) -> Optional[str]:
    if not data:
        return None
    if data[:4] == JAVA_MAGIC:
        return "Java serialized object"
    if data[:9] == DOTNET_MAGIC:
        return ".NET BinaryFormatter payload"
    if len(data) > 3 and data[0] == 0x80 and data[1] in (2, 3, 4, 5) and data[-1] == 0x2E:
        return "Python pickle"
    if data[:2] == RUBY_MAGIC:
        return "Ruby Marshal data"
    return None


def _analyze_php(text: str) -> dict:
    stripped = text.strip()
    info: dict = {"structure": "object" if stripped.startswith("O:") else "array"}
    match = PHP_OBJECT_RE.match(stripped)
    if match:
        info["class_name"] = match.group(2)
        info["declared_properties"] = int(match.group(3))
    fields = [m.group(2) for m in PHP_STRING_FIELD_RE.finditer(stripped)]
    if fields:
        info["string_field_names"] = fields[0::2] if len(fields) > 1 else fields
        info["string_values"] = fields
    return info


def _analyze_java(data: bytes) -> dict:
    info: dict = {"stream_length": len(data)}
    try:
        offset = len(JAVA_MAGIC)
        if data[offset:offset + 1] == b"r" and len(data) > offset + 3:
            name_len = int.from_bytes(data[offset + 1:offset + 3], "big")
            name = data[offset + 3:offset + 3 + name_len].decode("ascii", errors="replace")
            if name:
                info["class_name"] = name
    except Exception:
        pass
    return info


def _analyze_pickle(data: bytes) -> dict:
    return {"protocol": data[1] if len(data) > 1 else None, "stream_length": len(data)}


def _analyze_dotnet_binaryformatter(data: bytes) -> dict:
    return {"stream_length": len(data)}


def _analyze_ruby(data: bytes) -> dict:
    version = f"{data[0]}.{data[1]}" if len(data) > 1 else None
    return {"marshal_version": version, "stream_length": len(data)}


def _analyze_node_serialize(text: str) -> dict:
    return {"marker_count": text.count(NODE_SERIALIZE_MARK)}


def _analyze_xmldecoder(text: str) -> dict:
    classes = re.findall(r'class="(java\.[\w.$]+)"', text)
    info: dict = {}
    if classes:
        info["class_names"] = sorted(set(classes))
    return info


TEXT_ANALYZERS: Dict[str, Callable[[str], dict]] = {
    "PHP serialized object": _analyze_php,
    "PHP serialized array": _analyze_php,
    "node-serialize function payload": _analyze_node_serialize,
    "Java XMLDecoder XML": _analyze_xmldecoder,
}

BYTE_ANALYZERS: Dict[str, Callable[[bytes], dict]] = {
    "Java serialized object": _analyze_java,
    "Python pickle": _analyze_pickle,
    ".NET BinaryFormatter payload": _analyze_dotnet_binaryformatter,
    "Ruby Marshal data": _analyze_ruby,
}


def decode(value: str) -> Optional[DecodedPayload]:
    if not isinstance(value, str) or len(value) < 8:
        return None

    payload = DecodedPayload(original=value)
    current = value

    url_decoded = _url_decode(current)
    if url_decoded is not None:
        payload.encoding_chain.append("URL-encoded")
        current = url_decoded

    kind = classify_text(current)
    if kind:
        payload.decoded_text = current
        payload.signature = signatures.by_kind(kind)
        payload.analysis = TEXT_ANALYZERS.get(kind, lambda _t: {})(current)
        return payload

    raw = _hex_decode(current)
    encoding_label = "hex-encoded"
    if raw is None:
        raw = _base64_decode(current)
        encoding_label = "Base64-encoded"
    if raw is None:
        return None
    payload.encoding_chain.append(encoding_label)

    for _ in range(MAX_DECODE_LAYERS):
        gz = _gzip_decode(raw)
        if gz is None:
            break
        raw = gz
        payload.encoding_chain.append("gzip-compressed")

    text = _as_text(raw)
    if text:
        kind = classify_text(text)
        if kind:
            payload.decoded_text = text
            payload.signature = signatures.by_kind(kind)
            payload.analysis = TEXT_ANALYZERS.get(kind, lambda _t: {})(text)
            return payload

    kind = classify_bytes(raw)
    if kind:
        payload.decoded_bytes = raw
        payload.decoded_text = text
        payload.signature = signatures.by_kind(kind)
        payload.analysis = BYTE_ANALYZERS.get(kind, lambda _d: {})(raw)
        return payload

    return None


def decode_candidates(value: str) -> Optional[DecodedPayload]:
    result = decode(value)
    if result:
        return result
    decoded_once = unquote(value)
    if decoded_once == value:
        return None
    return decode(decoded_once)