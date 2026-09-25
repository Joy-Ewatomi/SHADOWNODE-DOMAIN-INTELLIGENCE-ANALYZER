import argparse
import json

from analyzer.core import analyze_domain
from analyzer.report import render_human_report


def main():
    parser = argparse.ArgumentParser(
        description="Passive OSINT domain intelligence analyzer."
    )

    parser.add_argument(
        "domain",
        help="Domain to analyze, for example example.com",
    )

    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Report format (default: json)",
    )

    args = parser.parse_args()

    result = analyze_domain(args.domain)

    if args.format == "text":
        print(render_human_report(result))
        return

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()