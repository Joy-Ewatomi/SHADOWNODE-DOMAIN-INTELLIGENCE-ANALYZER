from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError


def lookup_ip(ip: str) -> dict:
    result = {
        "ip": ip,
        "status": "no_data",
        "asn": None,
        "asn_cidr": None,
        "asn_country_code": None,
        "asn_registry": None,
        "asn_description": None,
        "network": {
            "cidr": None,
            "name": None,
            "handle": None,
        },
    }

    try:
        lookup = IPWhois(ip)

        data = lookup.lookup_rdap(
            depth=1
        )

        result["asn"] = data.get("asn")
        result["asn_cidr"] = data.get(
            "asn_cidr"
        )
        result["asn_country_code"] = data.get(
            "asn_country_code"
        )
        result["asn_registry"] = data.get(
            "asn_registry"
        )
        result["asn_description"] = data.get(
            "asn_description"
        )

        network = data.get(
            "network"
        ) or {}

        result["network"] = {
            "cidr": network.get("cidr"),
            "name": network.get("name"),
            "handle": network.get("handle"),
        }

        if result["asn"]:
            result["status"] = "success"
        else:
            result["status"] = "no_data"

    except (
        IPDefinedError,
        ValueError,
        OSError,
    ) as exc:
        result["status"] = "lookup_error"
        result["error"] = str(exc)

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


def get_asn_info(
    ip_addresses: list[str],
) -> dict:
    results = {}

    for ip in ip_addresses:
        results[ip] = lookup_ip(ip)

    return results
