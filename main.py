import json
import sys

from analyzer.core import analyze_domain


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py example.com")
        sys.exit(1)

    domain = sys.argv[1]

    result = analyze_domain(domain)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
