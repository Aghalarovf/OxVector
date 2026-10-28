import json
import re
from typing import List
from core.models import HttpRecord, Finding
from modules.deserialization import signatures

TYPE_KEYS = ("$type", "@type", "@class", "__type", "_class", "$class", "class", "javaClass")
CLASS_NAME_RE = re.compile(r"^[A-Za-z_][\w$]*(\.[A-Za-z_][\w$]*)+(,\s*[\w.\- =]+)?$")
TEXT_HINT_RE = re.compile(r'"(\$type|@type|@class|__type|javaClass)"\s*:\s*"([^"]+)"')


def _walk(node, found, depth=0):
    if depth > 8:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if k in TYPE_KEYS and isinstance(v, str) and CLASS_NAME_RE.match(v):
                found.append((k, v))
            else:
                _walk(v, found, depth + 1)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk(item, found, depth + 1)


def _extract(text: str):
    found = []
    if not text:
        return found
    try:
        _walk(json.loads(text), found)
    except Exception:
        for m in TEXT_HINT_RE.finditer(text[:65536]):
            if CLASS_NAME_RE.match(m.group(2)):
                found.append((m.group(1), m.group(2)))
    return found


class DeserializationTypeHintDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        marked = set()

        def mark(key, side):
            signature = signatures.by_type_key(key)
            if not signature or (signature["id"], side) in marked:
                return
            marked.add((signature["id"], side))
            findings.append(signatures.language_finding(signature, req.url, f'{side} JSON property "{key}"'))

        if req.body and "json" in (req.content_type or "").lower():
            for key, value in _extract(req.body)[:3]:
                mark(key, "Request")
                findings.append(Finding(
                    module="deserialization",
                    severity="medium",
                    title="Deserialization: Polymorphic Type Name in Request JSON",
                    location=req.url,
                    evidence=f'Request JSON contains "{key}": "{value}"',
                    vector_hint="Client-supplied class names suggest polymorphic deserialization (Json.NET TypeNameHandling, Jackson default typing, fastjson autotype) — test with alternative types",
                ))

        resp = record.response
        if resp.body and "json" in (resp.content_type or "").lower():
            for key, value in _extract(resp.body)[:1]:
                mark(key, "Response")
                findings.append(Finding(
                    module="deserialization",
                    severity="low",
                    title="Deserialization: Type Metadata Exposed in Response JSON",
                    location=req.url,
                    evidence=f'Response JSON contains "{key}" class metadata',
                    vector_hint="Type names in responses reveal backend classes and often indicate the same metadata is honored on input",
                ))
        return findings