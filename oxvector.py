import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.pycache_prefix = os.path.join(PROJECT_ROOT, "pycache")
sys.path.insert(0, PROJECT_ROOT)

from core.cli import parse_args
from core.intercept_reader import load_file
from core.engine import Engine
from core.logger import (
    print_banner,
    print_summary,
    print_findings,
    print_findings_by_request,
    export_json,
    export_html,
)


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    module_flags = {
        "xml": args.xml,
        "lfi": args.lfi,
        "jwt": args.jwt,
        "file_upload": args.file_upload,
        "cache": args.cache,
        "csrf": args.csrf,
        "clickjacking": args.clickjacking,
        "deserialization": args.deserialization,
        "oauth": args.oauth,
        "websocket": args.websocket,
        "info_disclosure": args.info_disclosure,
        "cookie_security": args.cookie_security,
    }
    if args.all:
        enabled = None
    else:
        selected = {name for name, flag in module_flags.items() if flag}
        enabled = selected if selected else None
    engine = Engine(enabled_modules=enabled)

    if args.live:
        from core.live_monitor import run_live
        live_verbosity = 2 if args.by_request_full else (1 if args.by_request else 0)
        run_live(
            args.input[0], engine,
            severity_filter=args.severity, verbose=args.verbose,
            output_path=args.output_json,
            verbosity=live_verbosity,
        )
        return

    all_records = []
    for path in args.input:
        print(f"  Loading: {path}")
        records = load_file(path, intercept=args.intercept)
        print(f"  Parsed {len(records)} records\n")
        all_records.extend(records)

    findings = engine.scan(all_records)

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

    if args.severity:
        allowed = {s.lower() for s in args.severity}
        other_findings = [f for f in other_findings if f.severity.lower() in allowed]
    elif not args.verbose:
        default_allowed = {"medium", "high", "critical"}
        other_findings = [f for f in other_findings if f.severity.lower() in default_allowed]

    findings = (
        other_findings + disclosure_findings + tech_findings
        + serialized_findings + cache_findings + websocket_connection_findings
    )

    show_payloads = args.by_request or args.by_request_full
    print_findings_by_request(findings, all_records, show_payloads=show_payloads, full=args.by_request_full)
    print_summary(findings, len(all_records))

    if args.output_json:
        export_json(findings, args.output_json)
    if args.output_html:
        export_html(findings, args.output_html)


if __name__ == "__main__":
    main()