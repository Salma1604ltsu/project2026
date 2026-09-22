from __future__ import annotations

import argparse
import json
import sys

from .scanner import APISecurityScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive, non-destructive API security assessment tool."
    )
    parser.add_argument("--url", required=True, help="Authorized API endpoint to assess.")
    parser.add_argument("--token", help="Bearer token for authentication checks.")
    parser.add_argument("--token-a", help="First authorized test principal token.")
    parser.add_argument("--token-b", help="Second authorized test principal token.")
    parser.add_argument("--samples", type=int, default=3, help="Rate-limit sample, 1-5.")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification.")
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    scanner = APISecurityScanner(timeout=args.timeout, verify_tls=not args.insecure)
    try:
        report = scanner.scan(
            args.url, token=args.token, token_a=args.token_a,
            token_b=args.token_b, samples=args.samples
        )
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Target: {report['target']}")
        print(f"HTTP status: {report['status_code']}\n")
        for finding in report["findings"]:
            print(f"[{finding['severity']}] {finding['check']}: {finding['title']}")
            print(f"  Evidence: {finding['evidence']}")
            print(f"  Fix: {finding['remediation']}\n")
        print("Summary:", json.dumps(report["summary"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
