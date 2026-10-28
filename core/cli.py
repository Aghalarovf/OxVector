import argparse
import sys
import os


def parse_args():
    parser = argparse.ArgumentParser(
        prog="oxvector",
        description="OxVector",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "input",
        nargs="+",
        help="Path(s) to Burp JSON / HAR / ZAP JSON / intercept JSON or JSONL file(s)",
    )
    parser.add_argument(
        "--xml",
        action="store_true",
        help="Run the XML module",
    )
    parser.add_argument(
        "--lfi",
        action="store_true",
        help="Run the LFI / Path Traversal module",
    )
    parser.add_argument(
        "--jwt",
        action="store_true",
        help="Run the JWT module",
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Run the Cache Poisoning module",
    )
    parser.add_argument(
        "--csrf",
        action="store_true",
        help="Run the CSRF module",
    )
    parser.add_argument(
        "--clickjacking",
        action="store_true",
        help="Run the Clickjacking module",
    )
    parser.add_argument(
        "--deserialization",
        action="store_true",
        help="Run the Insecure Deserialization module",
    )
    parser.add_argument(
        "--oauth",
        action="store_true",
        help="Run the OAuth module",
    )
    parser.add_argument(
        "--websocket",
        action="store_true",
        help="Run the WebSocket module",
    )
    parser.add_argument(
        "--info-disclosure",
        action="store_true",
        dest="info_disclosure",
        help="Run the Information Disclosure module",
    )
    parser.add_argument(
        "--cookie-security",
        action="store_true",
        dest="cookie_security",
        help="Run the Cookie Security module",
    )
    parser.add_argument(
        "--file-upload",
        action="store_true",
        dest="file_upload",
        help="Run the File Upload module",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all modules",
    )
    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        nargs="+",
        default=None,
        help="Filter output by severity: critical high medium low info",
    )
    parser.add_argument(
        "-o",
        "--output-json",
        metavar="FILE",
        default=None,
        dest="output_json",
        help="Export findings to JSON file (overwrites the file, no appending)",
    )
    parser.add_argument(
        "--output-html",
        metavar="FILE",
        default=None,
        help="Export findings to HTML report",
    )
    parser.add_argument(
        "--intercept",
        action="store_true",
        help="Read input files as intercept traffic logs (JSON array or JSONL)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Tail the input file live (requires --intercept, single file) and report findings as they occur",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the banner",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all severities, including LOW and INFO (default: only MEDIUM, HIGH, CRITICAL)",
    )
    parser.add_argument(
        "-v",
        action="store_true",
        dest="by_request",
        help="Default request-grouped output: [url] [method] [status], Findings, Payloads",
    )
    parser.add_argument(
        "-Vv",
        action="store_true",
        dest="by_request_full",
        help="Expand Payloads with the full ready-made payload data",
    )
    args = parser.parse_args()

    if args.live:
        if not args.intercept:
            print("[error] --live requires --intercept", file=sys.stderr)
            sys.exit(1)
        if len(args.input) != 1:
            print("[error] --live supports exactly one input file", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.input[0]):
            open(args.input[0], "a", encoding="utf-8").close()
    else:
        for path in args.input:
            if not os.path.isfile(path):
                print(f"[error] File not found: {path}", file=sys.stderr)
                sys.exit(1)

    return args