import html
import json
import sys
import textwrap
from datetime import datetime
from typing import List
from core.models import Finding

SEVERITY_COLOR = {
    "critical": "\033[38;5;129m",
    "high":     "\033[91m",
    "medium":   "\033[38;5;208m",
    "low":      "\033[92m",
    "info":     "\033[94m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BRIGHT_RED = "\033[91m"

METHOD_COLOR = {
    "GET":     "\033[92m",
    "POST":    "\033[94m",
    "HEAD":    "\033[38;5;130m",
    "OPTIONS": "\033[38;5;141m",
}
METHOD_DEFAULT_COLOR = "\033[90m"

STATUS_COLOR = {
    "1": "\033[38;5;213m",
    "2": "\033[92m",
    "3": "\033[94m",
    "4": "\033[91m",
    "5": "\033[38;5;141m",
}
STATUS_DEFAULT_COLOR = "\033[90m"


def _color(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    c = SEVERITY_COLOR.get(severity.lower(), "")
    return f"{c}{text}{RESET}"


def _severity_tag(severity: str) -> str:
    return f"[{_color(severity.upper(), severity)}]"


def _bold(text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{BOLD}{text}{RESET}"


def _green(text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{GREEN}{text}{RESET}"


def _bright_red(text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{BRIGHT_RED}{text}{RESET}"


def _yellow(text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{YELLOW}{text}{RESET}"


def _dim(text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{DIM}{text}{RESET}"


def _method_color(method: str) -> str:
    text = str(method)
    if not sys.stdout.isatty():
        return text
    c = METHOD_COLOR.get(text.upper(), METHOD_DEFAULT_COLOR)
    return f"{c}{text}{RESET}"


def _status_color(status) -> str:
    text = str(status)
    if not sys.stdout.isatty():
        return text
    c = STATUS_COLOR.get(text[:1], STATUS_DEFAULT_COLOR) if text else STATUS_DEFAULT_COLOR
    return f"{c}{text}{RESET}"


def print_banner():
    print(_bold("  OxVector\n"))


def print_live_header(path: str):
    print(_bold(f"  Live monitoring: {path}"))
    print(_dim("  Watching for new traffic... press Ctrl+C to stop\n"))


def print_summary(findings: List[Finding], record_count: int):
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(_bold("\n─── Scan Summary ──────────────────────────────────────────"))
    print(f"  Records analyzed : {record_count}")
    print(f"  Total findings   : {len(findings)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            print(f"  {_color(sev.upper().ljust(10), sev)} : {counts[sev]}")
    print(_bold("───────────────────────────────────────────────────────────\n"))


TOKEN_PREFIX = "Token    : "
MAX_LISTED_URLS = 100


def _jwt_lines(jwt: dict) -> List[str]:
    lines = [f"{TOKEN_PREFIX}{jwt['token']}"]
    lines.append(f"Algorithm: {jwt.get('algorithm') or 'not decodable'}")
    for label, key in (("Header", "header"), ("Payload", "payload")):
        value = jwt.get(key)
        if value is None:
            lines.append(f"{label}   : not decodable")
        else:
            lines.append(f"{label}:")
            for text in json.dumps(value, indent=2, ensure_ascii=False).splitlines():
                lines.append(f"  {text}")
    if jwt.get("timestamps"):
        lines.append("Timestamps:")
        for claim, formatted in jwt["timestamps"].items():
            lines.append(f"  {claim}: {formatted}")
    length = jwt.get("signature_length")
    if length is None:
        lines.append("Signature: not decodable")
    elif length == 0:
        lines.append("Signature: empty")
    else:
        hex_value = jwt.get("signature_hex", "")
        shown = hex_value[:32] + ("..." if len(hex_value) > 32 else "")
        lines.append(f"Signature: {length} bytes (binary), hex: {shown}")
    return lines


def print_finding(f: Finding, shown: set = None):
    label = _color(f"[{f.severity.upper()}]", f.severity)
    print(f"{label} {_bold(f.title)}")
    print(f"  {_dim('Module  :')} {f.module}")
    print(f"  {_dim('Location:')} {_yellow(f.location)}")
    print(f"  {_dim('Evidence:')} {f.evidence}")
    if f.vector_hint:
        print(f"  {_dim('Vector  :')} {f.vector_hint}")
    if f.confidence and f.confidence != "candidate":
        print(f"  {_dim('Confidence:')} {f.confidence}")
    urls = f.extra.get("urls") if f.extra else None
    if urls:
        print(f"  {_dim('URLs    :')} {len(urls)} found")
        for url in urls[:MAX_LISTED_URLS]:
            print(f"    {url}")
        if len(urls) > MAX_LISTED_URLS:
            print(f"    ... and {len(urls) - MAX_LISTED_URLS} more (see JSON report)")
    jwt = f.extra.get("jwt") if f.extra else None
    if jwt:
        print(f"  {_dim('JWT     :')} decoded token")
        for line in _jwt_lines(jwt):
            if line.startswith(TOKEN_PREFIX):
                print(f"    {TOKEN_PREFIX}{_green(line[len(TOKEN_PREFIX):])}")
            else:
                print(f"    {line}")
    xml = f.extra.get("xml") if f.extra else None
    if xml:
        source = f.extra.get("xml_source", "body")
        print(f"  {_dim('XML     :')} full XML from {source}")
        for line in xml.splitlines():
            print(f"    {_green(line)}")
    print()


def print_findings(findings: List[Finding]):
    if not findings:
        print(_dim("  No findings detected.\n"))
        return

    grouped: dict = {}
    for f in findings:
        grouped.setdefault(f.module, []).append(f)

    shown: set = set()
    for module, items in sorted(grouped.items()):
        print(_bold(f"\n══ {module.upper()} ({'%d finding%s' % (len(items), 's' if len(items) > 1 else '')}) ══"))
        for f in items:
            print_finding(f, shown)


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity.lower(), -1)


def build_request_index(records) -> dict:
    index = {}
    for record in records:
        url = record.request.url
        if url not in index:
            index[url] = {
                "method": record.request.method,
                "status": record.response.status,
            }
    return index


def _basic_payload(f: Finding) -> List[str]:
    return [f.vector_hint] if f.vector_hint else []


def _full_payloads(f: Finding) -> List[str]:
    payloads = list(_basic_payload(f))

    jwt = f.extra.get("jwt") if f.extra else None
    if jwt:
        payloads.append(f"JWT token: {jwt.get('token')}")
        if jwt.get("algorithm"):
            payloads.append(f"JWT algorithm: {jwt.get('algorithm')}")
        if jwt.get("payload"):
            payloads.append("JWT payload: " + json.dumps(jwt["payload"], ensure_ascii=False))

    xml = f.extra.get("xml") if f.extra else None
    if xml:
        payloads.append(f"XML payload:\n{xml}")

    urls = f.extra.get("urls") if f.extra else None
    if urls:
        for url in urls[:MAX_LISTED_URLS]:
            payloads.append(f"Related URL: {url}")

    return payloads


def _print_payload_block(lines: List[str]):
    printed_any = False
    for text in lines:
        printed_any = True
        parts = text.splitlines() or [""]
        for i, part in enumerate(parts):
            prefix = "   " if i == 0 else "      "
            print(f"{prefix}{_green(part)}")
    if not printed_any:
        print(_dim("   None"))


def _is_serialized_language(f: Finding) -> bool:
    return bool(f.extra and f.extra.get("serialized_language"))


def _serialized_groups(items: List[Finding]) -> List[dict]:
    groups: dict = {}
    order: List[str] = []
    for f in items:
        info = f.extra["serialized_language"]
        key = info.get("id") or info.get("language")
        if key not in groups:
            groups[key] = {"info": info, "sources": []}
            order.append(key)
        source = info.get("source")
        if source and source not in groups[key]["sources"]:
            groups[key]["sources"].append(source)
    return [groups[key] for key in order]


def _print_field(label: str, text: str, width: int = 110):
    pad = 6 + len(label) + 1
    lines = textwrap.wrap(str(text), width=max(width - pad, 30)) or [""]
    print(f"      {_dim(label)} {lines[0]}")
    for line in lines[1:]:
        print(" " * pad + line)


def _print_serialized_language(items: List[Finding]):
    print("Serialized Language:")
    for group in _serialized_groups(items):
        info = group["info"]
        runtime = info.get("runtime")
        header = info.get("language") or "Unknown"
        if runtime:
            header += f" ({runtime})"
        print(f"   {_green(header)}")
        if info.get("confidence"):
            _print_field("Confidence:", info["confidence"])
        if info.get("format"):
            _print_field("Format    :", info["format"])
        for source in group["sources"]:
            _print_field("Found in  :", source)
        if info.get("encoding_chain"):
            _print_field("Decoded   :", " -> ".join(info["encoding_chain"]))
        if info.get("decoded_preview"):
            _print_field("Preview   :", info["decoded_preview"])
        analysis = info.get("analysis") or {}
        if analysis.get("class_name"):
            _print_field("Class     :", analysis["class_name"])
        if analysis.get("class_names"):
            _print_field("Classes   :", ", ".join(analysis["class_names"]))
        if analysis.get("string_field_names"):
            _print_field("Fields    :", ", ".join(analysis["string_field_names"]))
        if info.get("indicators"):
            _print_field("Indicators:", "; ".join(info["indicators"]))
        if info.get("details"):
            _print_field("Details   :", info["details"])
        if info.get("frameworks"):
            _print_field("Frameworks:", ", ".join(info["frameworks"]))
        if info.get("risk"):
            _print_field("Risk      :", info["risk"])
        if info.get("remediation"):
            _print_field("Fix       :", info["remediation"])


def _websocket_reason_entries(items: List[Finding]) -> List[tuple]:
    seen = set()
    entries = []
    for f in items:
        for entry in (f.extra or {}).get("websocket_reasons") or []:
            key = (entry.get("source", ""), entry.get("detail", ""))
            if key in seen:
                continue
            seen.add(key)
            entries.append(key)
    return entries


def _print_websocket_reasons(entries: List[tuple]):
    width = max(len(source) for source, _ in entries)
    for source, detail in entries:
        print(f"   {_dim(source.ljust(width) + ' :')} {_green(detail)}")


def _print_cache_section(items: List[Finding]):
    print("Web Cache:")
    for f in items:
        label = _color(f.severity.upper(), f.severity)
        print(f"   [{label}] {f.title}")
        lines = [ln for ln in (f.evidence or "").split("\n") if ln.strip()]
        header_lines = [ln for ln in lines if not ln.startswith("[Risk Score")]
        risk_lines = [ln for ln in lines if ln.startswith("[Risk Score")]
        if header_lines:
            print(f"      {_dim('Headers :')} {header_lines[0]}")
            for ln in header_lines[1:]:
                print(f"                {ln}")
        if risk_lines:
            print(f"      {_dim('Risk    :')} {risk_lines[0].strip('[]')}")
        if f.vector_hint:
            print(f"      {_dim('Hint    :')} {f.vector_hint}")


def print_findings_by_request(findings: List[Finding], records, show_payloads: bool = False, full: bool = False):
    if not findings:
        print(_dim("  No findings detected.\n"))
        return

    index = build_request_index(records)
    grouped: dict = {}
    order: List[str] = []
    for f in findings:
        req_idx = f.extra.get("request_index") if f.extra else None
        key = ("req", req_idx) if isinstance(req_idx, int) else ("url", f.location)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(f)

    for key in order:
        items = grouped[key]
        url = items[0].location
        meta = index.get(url, {})
        if key[0] == "req" and 0 <= key[1] < len(records):
            rec = records[key[1]]
            meta = {"method": rec.request.method, "status": rec.response.status}
        method = meta.get("method", "?")
        status = meta.get("status", "?")
        print(_bold(f"[{_yellow(url)}] [{_method_color(method)}] [{_status_color(status)}]"))
        tech_items = [f for f in items if f.extra and f.extra.get("technology")]
        serialized_items = [f for f in items if _is_serialized_language(f)]
        disclosure_items = [
            f for f in items
            if f.module == "info_disclosure"
            and not (f.extra and f.extra.get("technology"))
            and not _is_serialized_language(f)
        ]
        cache_items = [
            f for f in items
            if f.module == "cache"
            and not (f.extra and f.extra.get("technology"))
            and not _is_serialized_language(f)
        ]
        websocket_conn_items = [
            f for f in items
            if f.module == "websocket"
            and f.extra and f.extra.get("websocket_detected")
        ]
        other_items = [
            f for f in items
            if not (f.extra and f.extra.get("technology"))
            and not _is_serialized_language(f)
            and f.module != "info_disclosure"
            and f.module != "cache"
            and not (f.extra and f.extra.get("websocket_detected"))
        ]
        module_order: List[str] = []
        module_best: dict = {}
        for group in (other_items, disclosure_items, tech_items, websocket_conn_items):
            for f in group:
                if f.module not in module_best:
                    module_order.append(f.module)
                    module_best[f.module] = f
                elif _severity_rank(f.severity) > _severity_rank(module_best[f.module].severity):
                    module_best[f.module] = f
        for module in module_order:
            f = module_best[module]
            print(f"Findings: {_bright_red(module.upper().replace('_', ' '))} {_severity_tag(f.severity)}")
        reason_items = [f for f in other_items if f.extra and f.extra.get("reason")]
        websocket_entries = _websocket_reason_entries([f for f in other_items if f.module == "websocket"])
        if reason_items or websocket_entries:
            print("Reasons:")
            for f in reason_items:
                label = _color(f.severity.upper(), f.severity)
                print(f"   [{label}] {f.title}")
                print(f"      {_dim('Reason  :')} {f.extra['reason']}")
                if f.evidence and f.evidence != f.extra["reason"]:
                    print(f"      {_dim('Evidence:')} {f.evidence}")
            if websocket_entries:
                _print_websocket_reasons(websocket_entries)
        if tech_items:
            print("Technologies:")
            for f in tech_items:
                name = f.extra["technology"]
                version = f.extra.get("version")
                category = f.extra.get("category", "Unknown")
                shown = f"{name} {version}" if version else name
                print(f"   {_green(shown + ' (' + category + ')')}")
        if serialized_items:
            _print_serialized_language(serialized_items)
        if websocket_conn_items:
            print("WebSocket:")
            for f in websocket_conn_items:
                label = _color(f.severity.upper(), f.severity)
                title = f.title.replace("WebSocket: ", "", 1)
                print(f"   [{label}] {title}")
                print(f"      {_dim('Evidence:')} {f.evidence}")
                if f.vector_hint:
                    print(f"      {_dim('Hint    :')} {f.vector_hint}")
        if cache_items:
            _print_cache_section(cache_items)
        if disclosure_items:
            print("Disclosure:")
            for f in disclosure_items:
                label = _color(f.severity.upper(), f.severity)
                print(f"   [{label}] {f.title}")
                print(f"      {_dim('Evidence:')} {f.evidence}")
                if f.vector_hint:
                    print(f"      {_dim('Hint    :')} {f.vector_hint}")
        payload_items = [f for f in other_items if f.module != "cookie_security"]
        if show_payloads and payload_items:
            print("Payloads:")
            payload_lines: List[str] = []
            for f in payload_items:
                payload_lines.extend(_full_payloads(f) if full else _basic_payload(f))
            _print_payload_block(payload_lines)
        print()


def export_json(findings: List[Finding], path: str):
    data = []
    for f in findings:
        data.append({
            "module": f.module,
            "severity": f.severity,
            "title": f.title,
            "location": f.location,
            "evidence": f.evidence,
            "vector_hint": f.vector_hint,
            "confidence": f.confidence,
            "extra": f.extra,
        })
    with open(path, "w", encoding="utf-8") as fp:
        json.dump({"generated": datetime.utcnow().isoformat(), "findings": data}, fp, indent=2)
    print(f"  Report saved → {path}")


def export_html(findings: List[Finding], path: str):
    rows = ""
    for f in findings:
        sev_class = html.escape(f.severity.lower())
        xml = f.extra.get("xml") if f.extra else None
        xml_block = ""
        if xml:
            xml_block = (
                f'<pre class="xml">{html.escape(xml)}</pre>'
            )
        jwt = f.extra.get("jwt") if f.extra else None
        if jwt:
            rendered = []
            for line in _jwt_lines(jwt):
                if line.startswith(TOKEN_PREFIX):
                    rendered.append(
                        html.escape(TOKEN_PREFIX)
                        + '<span class="tok">' + html.escape(line[len(TOKEN_PREFIX):]) + '</span>'
                    )
                else:
                    rendered.append(html.escape(line))
            xml_block += '<pre class="jwt">' + chr(10).join(rendered) + '</pre>'
        urls = f.extra.get("urls") if f.extra else None
        if urls:
            xml_block += '<pre class="urls">' + html.escape(chr(10).join(urls)) + '</pre>'
        rows += f"""
        <tr class="sev-{sev_class}">
          <td><span class="badge {sev_class}">{html.escape(f.severity.upper())}</span></td>
          <td>{html.escape(f.module)}</td>
          <td>{html.escape(f.title)}</td>
          <td class="mono loc">{html.escape(f.location)}</td>
          <td>{html.escape(f.evidence)}{xml_block}</td>
          <td class="mono">{html.escape(f.vector_hint or "")}</td>
        </tr>"""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OxVector Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; padding: 2rem; }}
  h1 {{ color: #58a6ff; margin-bottom: 0.25rem; font-size: 1.4rem; }}
  p.sub {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: #161b22; color: #8b949e; text-align: left; padding: 0.6rem 0.8rem;
        border-bottom: 1px solid #30363d; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.05em; font-size: 0.75rem; }}
  td {{ padding: 0.55rem 0.8rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .mono {{ font-family: 'Courier New', monospace; font-size: 0.8rem; color: #79c0ff; word-break: break-all; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px;
            font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em; }}
  .badge.critical, .badge.high {{ background: #3d1f1f; color: #f85149; }}
  .badge.medium  {{ background: #3d2d1a; color: #e3b341; }}
  .badge.low     {{ background: #1a2d3d; color: #58a6ff; }}
  .badge.info    {{ background: #1a2d2d; color: #39d353; }}
  .mono.loc {{ color: #e3b341; }}
  pre.urls {{ margin-top: 0.5rem; padding: 0.6rem; background: #161b22; border: 1px solid #30363d;
            border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.78rem;
            color: #c9d1d9; white-space: pre-wrap; word-break: break-all; }}
  .tok {{ color: #3fb950; }}
  pre.jwt {{ margin-top: 0.5rem; padding: 0.6rem; background: #161b22; border: 1px solid #30363d;
            border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.78rem;
            color: #79c0ff; white-space: pre-wrap; word-break: break-all; }}
  pre.xml {{ margin-top: 0.5rem; padding: 0.6rem; background: #161b22; border: 1px solid #30363d;
            border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.78rem;
            color: #3fb950; white-space: pre-wrap; word-break: break-all; }}
</style>
</head>
<body>
<h1>OxVector Report</h1>
<p class="sub">Generated: {datetime.utcnow().isoformat()} UTC &nbsp;|&nbsp; Total findings: {len(findings)}</p>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Module</th><th>Title</th>
      <th>Location</th><th>Evidence</th><th>Vector Hint</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fp:
        fp.write(page)
    print(f"  Report saved → {path}")