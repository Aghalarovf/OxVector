import json
import sys
import base64
from urllib.parse import urlparse, parse_qs
from typing import List
from core.models import Request, Response, HttpRecord


def _parse_content_type(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.split(";")[0].strip().lower()
    return ""


def _headers_to_dict(headers_raw) -> dict:
    if isinstance(headers_raw, dict):
        result = {}
        for k, v in headers_raw.items():
            key = k.lower()
            if key == "set-cookie" and key in result:
                result[key] = result[key] + "\n" + v
            else:
                result[key] = v
        return result
    if isinstance(headers_raw, list):
        result = {}
        for item in headers_raw:
            if isinstance(item, dict):
                name = item.get("name", item.get("key", "")).lower()
                value = item.get("value", "")
                if name == "set-cookie" and name in result:
                    result[name] = result[name] + "\n" + value
                else:
                    result[name] = value
        return result
    return {}


def _parse_params(url: str, body: str, content_type: str) -> dict:
    params = {}
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for k, v in qs.items():
        params[k] = v[0] if len(v) == 1 else v

    if body:
        if "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import parse_qs as pqs
            form = pqs(body, keep_blank_values=True)
            for k, v in form.items():
                params[k] = v[0] if len(v) == 1 else v
        elif "application/json" in content_type:
            try:
                json_body = json.loads(body)
                if isinstance(json_body, dict):
                    params.update(json_body)
            except Exception:
                pass
    return params


def _decode_body(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        text = raw.get("text", "")
        if text:
            return text
        encoded = raw.get("encoding", "")
        data = raw.get("data", "")
        if encoded == "base64" and data:
            try:
                return base64.b64decode(data).decode("utf-8", errors="replace")
            except Exception:
                return ""
    return ""


def _from_burp_item(item: dict, source: str) -> HttpRecord:
    req_raw = item.get("request", {})
    resp_raw = item.get("response", {})

    req_headers = _headers_to_dict(req_raw.get("headers", {}))
    req_body = _decode_body(req_raw.get("body") or req_raw.get("body_preview"))
    req_ct = _parse_content_type(req_headers)
    req_url = req_raw.get("url", item.get("url", ""))
    req_method = req_raw.get("method", "GET").upper()
    req_params = _parse_params(req_url, req_body, req_ct)

    resp_headers = _headers_to_dict(resp_raw.get("headers", {}))
    resp_body = _decode_body(resp_raw.get("body") or resp_raw.get("body_preview"))
    resp_ct = _parse_content_type(resp_headers)
    resp_status = _to_int(resp_raw.get("status", resp_raw.get("status_code", 0)))

    request = Request(
        method=req_method,
        url=req_url,
        headers=req_headers,
        params=req_params,
        body=req_body if req_body else None,
        content_type=req_ct,
        raw=json.dumps(req_raw),
    )
    response = Response(
        status=resp_status,
        headers=resp_headers,
        body=resp_body if resp_body else None,
        content_type=resp_ct,
    )
    return HttpRecord(request=request, response=response, source_file=source)


def _from_har_entry(entry: dict, source: str) -> HttpRecord:
    req_raw = entry.get("request", {})
    resp_raw = entry.get("response", {})

    req_headers = _headers_to_dict(req_raw.get("headers", []))
    req_body_obj = req_raw.get("postData", {})
    req_body = req_body_obj.get("text", "") if req_body_obj else ""
    req_ct = _parse_content_type(req_headers)
    req_url = req_raw.get("url", "")
    req_method = req_raw.get("method", "GET").upper()
    req_params = _parse_params(req_url, req_body, req_ct)

    resp_headers = _headers_to_dict(resp_raw.get("headers", []))
    resp_content = resp_raw.get("content", {})
    resp_body = resp_content.get("text", "")
    resp_ct = _parse_content_type(resp_headers)
    resp_status = int(resp_raw.get("status", 0))

    request = Request(
        method=req_method,
        url=req_url,
        headers=req_headers,
        params=req_params,
        body=req_body if req_body else None,
        content_type=req_ct,
    )
    response = Response(
        status=resp_status,
        headers=resp_headers,
        body=resp_body if resp_body else None,
        content_type=resp_ct,
    )
    return HttpRecord(request=request, response=response, source_file=source)


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _from_intercept_item(item: dict, source: str) -> HttpRecord:
    req_raw = item.get("request") or {}
    resp_raw = item.get("response") or {}

    req_headers = _headers_to_dict(req_raw.get("headers", {}))
    req_body = _decode_body(req_raw.get("body") or req_raw.get("body_preview"))
    req_ct = _parse_content_type(req_headers)
    req_url = req_raw.get("url") or item.get("url", "")
    req_method = str(req_raw.get("method", "GET")).upper()
    req_params = _parse_params(req_url, req_body, req_ct)

    resp_headers = _headers_to_dict(resp_raw.get("headers", {}))
    resp_body = _decode_body(resp_raw.get("body") or resp_raw.get("body_preview"))
    resp_ct = _parse_content_type(resp_headers)
    resp_status = _to_int(resp_raw.get("status_code", resp_raw.get("status", 0)))

    request = Request(
        method=req_method,
        url=req_url,
        headers=req_headers,
        params=req_params,
        body=req_body if req_body else None,
        content_type=req_ct,
        raw=json.dumps(req_raw),
    )
    response = Response(
        status=resp_status,
        headers=resp_headers,
        body=resp_body if resp_body else None,
        content_type=resp_ct,
    )
    return HttpRecord(request=request, response=response, source_file=source)


def _unwrap_intercept_payload(data) -> list:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if "request" in data:
            return [data]
        for key in ("items", "records", "entries", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _read_intercept_items(path: str) -> list:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        text = f.read()

    if not path.lower().endswith((".jsonl", ".ndjson")):
        try:
            return _unwrap_intercept_payload(json.loads(text))
        except json.JSONDecodeError:
            pass

    items = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            items.extend(_unwrap_intercept_payload(json.loads(line)))
        except json.JSONDecodeError:
            print(
                f"  [warning] {path}:{number} is not valid JSON, skipped",
                file=sys.stderr,
            )
    return items


def parse_intercept_item(item: dict, source: str) -> HttpRecord:
    return _from_intercept_item(item, source)


def unwrap_intercept_payload(data) -> list:
    return _unwrap_intercept_payload(data)


def load_intercept_file(path: str) -> List[HttpRecord]:
    records = []
    for item in _read_intercept_items(path):
        if "request" in item:
            records.append(_from_intercept_item(item, path))
    return records


def load_file(path: str, intercept: bool = False) -> List[HttpRecord]:
    if intercept:
        return load_intercept_file(path)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    records = []

    if isinstance(data, list):
        for item in data:
            if "request" in item and "response" in item:
                if "headers" in item.get("request", {}) and isinstance(
                    item["request"]["headers"], list
                ):
                    if any(
                        "name" in h for h in item["request"]["headers"]
                    ):
                        records.append(_from_har_entry(item, path))
                    else:
                        records.append(_from_burp_item(item, path))
                else:
                    records.append(_from_burp_item(item, path))

    elif isinstance(data, dict):
        if "log" in data:
            entries = data["log"].get("entries", [])
            for entry in entries:
                records.append(_from_har_entry(entry, path))
        elif "items" in data:
            for item in data["items"]:
                records.append(_from_burp_item(item, path))

    return records