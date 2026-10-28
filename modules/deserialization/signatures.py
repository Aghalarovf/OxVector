import json
import os
from typing import Optional

from core.models import Finding

SIGNATURES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "serialized_signatures.json"
)

_index = None


def _build_index():
    index = {"kind": {}, "content_type": {}, "type_key": {}, "viewstate": None}
    try:
        with open(SIGNATURES_PATH, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError):
        return index
    for sig in data.get("signatures", []):
        for kind in sig.get("kinds", []):
            index["kind"][kind] = sig
        for ctype in sig.get("content_types", []):
            index["content_type"][ctype.lower()] = sig
        for key in sig.get("type_keys", []):
            index["type_key"][key] = sig
        if sig.get("viewstate"):
            index["viewstate"] = sig
    return index


def _get_index():
    global _index
    if _index is None:
        _index = _build_index()
    return _index


def by_kind(kind: str) -> Optional[dict]:
    return _get_index()["kind"].get(kind)


def by_content_type(content_type: str) -> Optional[dict]:
    return _get_index()["content_type"].get((content_type or "").lower())


def by_type_key(key: str) -> Optional[dict]:
    return _get_index()["type_key"].get(key)


def viewstate() -> Optional[dict]:
    return _get_index()["viewstate"]


def language_finding(signature: dict, location: str, source: str, decoded=None) -> Finding:
    info = {
        "id": signature.get("id"),
        "language": signature.get("language"),
        "runtime": signature.get("runtime"),
        "confidence": signature.get("confidence"),
        "format": signature.get("format"),
        "indicators": list(signature.get("indicators", [])),
        "details": signature.get("details"),
        "frameworks": list(signature.get("frameworks", [])),
        "risk": signature.get("risk"),
        "remediation": signature.get("remediation"),
        "source": source,
    }
    evidence = f"{source} ({info['format']})"
    if decoded is not None:
        info["encoding_chain"] = list(decoded.encoding_chain)
        info["decoded_preview"] = _preview(decoded.decoded_text) if decoded.decoded_text else None
        info["analysis"] = dict(decoded.analysis)
        if decoded.encoding_chain:
            evidence += f", decoded via {decoded.encoding_summary}"
    return Finding(
        module="deserialization",
        severity="info",
        title=f"Serialized Language: {info['language']}",
        location=location,
        evidence=evidence,
        extra={"serialized_language": info},
    )


def _preview(text: str, n: int = 160) -> str:
    text = text.strip()
    return text if len(text) <= n else text[:n] + "..."