import dns.exception
import dns.resolver


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "SOA",
    "CAA",
]


def get_dns_records(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")

    results = {}

    for record_type in RECORD_TYPES:
        key = record_type.lower()

        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=5,
            )

            records = []

            for answer in answers:
                records.append(
                    answer.to_text()
                )

            results[key] = {
                "records": records,
                "status": "success",
            }

        except dns.resolver.NXDOMAIN:
            results[key] = {
                "records": [],
                "status": "nxdomain",
            }

        except dns.resolver.NoAnswer:
            results[key] = {
                "records": [],
                "status": "no_answer",
            }

        except dns.resolver.NoNameservers:
            results[key] = {
                "records": [],
                "status": "no_nameservers",
            }

        except dns.exception.Timeout:
            results[key] = {
                "records": [],
                "status": "timeout",
            }

        except Exception as exc:
            results[key] = {
                "records": [],
                "status": "error",
                "error": str(exc),
            }

    return results


def resolve_hostname(hostname: str) -> dict:
    """
    Passively resolve a hostname using the system DNS resolver.

    Returns IPv4 and IPv6 addresses without making HTTP/TLS
    connections to the target.
    """

    hostname = (
        hostname
        .strip()
        .lower()
        .rstrip(".")
    )

    result = {
        "hostname": hostname,
        "ipv4": [],
        "ipv6": [],
        "status": "no_answer",
    }

    statuses = []

    for record_type, result_key in [
        ("A", "ipv4"),
        ("AAAA", "ipv6"),
    ]:
        try:
            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=5,
            )

            statuses.append("success")

            for answer in answers:
                value = answer.to_text()

                if value not in result[result_key]:
                    result[result_key].append(value)

        except dns.resolver.NXDOMAIN:
            statuses.append("nxdomain")

        except dns.resolver.NoAnswer:
            statuses.append("no_answer")

        except dns.resolver.NoNameservers:
            statuses.append("no_nameservers")

        except dns.exception.Timeout:
            statuses.append("timeout")

        except Exception as exc:
            statuses.append("error")

            result.setdefault(
                "errors",
                [],
            ).append({
                "record_type": record_type,
                "error": str(exc),
            })

    if result["ipv4"] or result["ipv6"]:
        result["status"] = "success"

    elif "timeout" in statuses:
        result["status"] = "timeout"

    elif "error" in statuses:
        result["status"] = "error"

    elif (
        statuses
        and all(
            status == "nxdomain"
            for status in statuses
        )
    ):
        result["status"] = "nxdomain"

    elif "no_nameservers" in statuses:
        result["status"] = "no_nameservers"

    else:
        result["status"] = "no_answer"

    result["resolves"] = bool(
        result["ipv4"] or result["ipv6"]
    )

    return result
