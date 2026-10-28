import json
import os
import sys
import time
from datetime import datetime, timezone

from core.intercept_reader import load_intercept_file
from core.logger import print_findings_by_request, print_live_header

POLL_INTERVAL = 1.0


def _resolve_severity_filter(severity_filter, verbose: bool):
    if severity_filter:
        return {s.lower() for s in severity_filter}
    if not verbose:
        return {"medium", "high", "critical"}
    return None


def _load_records_safe(path: str):
    try:
        return load_intercept_file(path)
    except (OSError, ValueError):
        return None


def _finding_to_dict(record, finding, timestamp: str) -> dict:
    return {
        "module": finding.module,
        "category": finding.module,
        "severity": finding.severity,
        "title": finding.title,
        "location": finding.location,
        "url": finding.location,
        "method": record.request.method if record and record.request else None,
        "evidence": finding.evidence,
        "detail": finding.evidence,
        "vector_hint": finding.vector_hint,
        "matched_on": finding.vector_hint,
        "confidence": finding.confidence,
        "timestamp": timestamp,
        "extra": finding.extra,
    }


def _split_findings(findings, allowed):
    tech_findings = [f for f in findings if f.extra and f.extra.get("technology")]
    serialized_findings = [f for f in findings if f.extra and f.extra.get("serialized_language")]
    disclosure_findings = [
        f for f in findings
        if f.module == "info_disclosure"
        and not (f.extra and f.extra.get("technology"))
        and not (f.extra and f.extra.get("serialized_language"))
    ]
    cache_findings = [
        f for f in findings
        if f.module == "cache"
        and not (f.extra and f.extra.get("technology"))
        and not (f.extra and f.extra.get("serialized_language"))
    ]
    websocket_connection_findings = [
        f for f in findings
        if f.module == "websocket"
        and f.extra and f.extra.get("websocket_detected")
    ]
    other_findings = [
        f for f in findings
        if not (f.extra and f.extra.get("technology"))
        and not (f.extra and f.extra.get("serialized_language"))
        and f.module != "info_disclosure"
        and f.module != "cache"
        and not (f.extra and f.extra.get("websocket_detected"))
    ]
    if allowed is not None:
        other_findings = [f for f in other_findings if f.severity.lower() in allowed]
    return (
        other_findings + disclosure_findings + tech_findings
        + serialized_findings + cache_findings + websocket_connection_findings
    )


def _write_live_json(all_findings: list, output_path: str):
    payload = {"generated": datetime.now(timezone.utc).isoformat(), "findings": all_findings}
    tmp_path = f"{output_path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)
        os.replace(tmp_path, output_path)
    except OSError as exc:
        print(f"[warn] could not write {output_path}: {exc}", file=sys.stderr)


def run_live(path: str, engine, severity_filter=None, verbose: bool = False,
             poll_interval: float = POLL_INTERVAL, output_path: str = None,
             verbosity: int = 0):
    allowed = _resolve_severity_filter(severity_filter, verbose)
    show_payloads = verbosity >= 1
    full = verbosity >= 2
    print_live_header(path)

    seen = 0
    all_findings = []
    if output_path:
        _write_live_json(all_findings, output_path)

    try:
        while True:
            records = _load_records_safe(path)
            if records is not None and len(records) > seen:
                new_records = records[seen:]
                seen = len(records)
                dirty = False
                for record in new_records:
                    findings = engine.scan([record])
                    findings = _split_findings(findings, allowed)
                    if not findings:
                        continue
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print_findings_by_request(findings, [record], show_payloads=show_payloads, full=full)
                    for finding in findings:
                        all_findings.append(_finding_to_dict(record, finding, timestamp))
                    dirty = True
                if dirty and output_path:
                    _write_live_json(all_findings, output_path)
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("\n  Live monitoring stopped.\n", file=sys.stderr)
        if output_path:
            _write_live_json(all_findings, output_path)