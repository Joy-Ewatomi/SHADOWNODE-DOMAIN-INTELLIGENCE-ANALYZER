import requests


RDAP_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)


def get_rdap_info(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")

    try:
        bootstrap_response = requests.get(
            RDAP_BOOTSTRAP_URL,
            timeout=10,
        )

        if bootstrap_response.status_code >= 400:
            return {
                "available": False,
                "lookup_status": "bootstrap_http_error",
                "status_code": bootstrap_response.status_code,
                "reason": bootstrap_response.reason,
                "error": (
                    "RDAP bootstrap request failed"
                ),
            }

        try:
            bootstrap_data = (
                bootstrap_response.json()
            )
        except ValueError as exc:
            return {
                "available": False,
                "lookup_status": "bootstrap_invalid_json",
                "error": str(exc),
            }

        rdap_url = find_rdap_server(
            domain,
            bootstrap_data,
        )

        if not rdap_url:
            return {
                "available": False,
                "lookup_status": "no_server",
                "error": "No RDAP server found",
            }

        url = (
            rdap_url.rstrip("/")
            + "/domain/"
            + domain
        )

        try:
            response = requests.get(
                url,
                timeout=10,
                headers={
                    "Accept": (
                        "application/rdap+json, "
                        "application/json"
                    ),
                },
            )
        except requests.exceptions.Timeout as exc:
            return {
                "available": False,
                "lookup_status": "timeout",
                "error": str(exc),
            }
        except requests.exceptions.ConnectionError as exc:
            return {
                "available": False,
                "lookup_status": "connection_error",
                "error": str(exc),
            }
        except requests.exceptions.RequestException as exc:
            return {
                "available": False,
                "lookup_status": "request_error",
                "error": str(exc),
            }

        if response.status_code == 404:
            return {
                "available": False,
                "lookup_status": "not_found",
                "status_code": response.status_code,
                "reason": response.reason,
                "error": "Domain not found in RDAP",
            }

        if response.status_code >= 400:
            return {
                "available": False,
                "lookup_status": "http_error",
                "status_code": response.status_code,
                "reason": response.reason,
                "error": (
                    "RDAP domain request failed"
                ),
            }

        try:
            data = response.json()
        except ValueError as exc:
            return {
                "available": False,
                "lookup_status": "invalid_json",
                "status_code": response.status_code,
                "error": str(exc),
            }

        parsed = parse_rdap_response(data)
        parsed["lookup_status"] = "success"

        return parsed

    except requests.exceptions.Timeout as exc:
        return {
            "available": False,
            "lookup_status": "bootstrap_timeout",
            "error": str(exc),
        }

    except requests.exceptions.ConnectionError as exc:
        return {
            "available": False,
            "lookup_status": "bootstrap_connection_error",
            "error": str(exc),
        }

    except requests.exceptions.RequestException as exc:
        return {
            "available": False,
            "lookup_status": "bootstrap_request_error",
            "error": str(exc),
        }

    except Exception as exc:
        return {
            "available": False,
            "lookup_status": "error",
            "error": str(exc),
        }


def find_rdap_server(
    domain: str,
    bootstrap_data: dict,
):
    tld = domain.rsplit(".", 1)[-1].lower()

    for service in bootstrap_data.get(
        "services",
        [],
    ):
        tlds, urls = service

        if tld in [
            item.lower().lstrip(".")
            for item in tlds
        ]:
            if urls:
                return urls[0]

    return None


def parse_rdap_response(data: dict) -> dict:
    result = {
        "available": True,
        "handle": data.get("handle"),
        "ldh_name": data.get("ldhName"),
        "unicode_name": data.get("unicodeName"),
        "status": data.get("status", []),
        "nameservers": [],
        "events": [],
        "entities": [],
    }

    for nameserver in data.get(
        "nameservers",
        [],
    ):
        name = nameserver.get("ldhName")

        if name:
            result["nameservers"].append(name)

    for event in data.get("events", []):
        result["events"].append({
            "event_action": event.get(
                "eventAction"
            ),
            "event_date": event.get(
                "eventDate"
            ),
        })

    for entity in data.get("entities", []):
        result["entities"].append({
            "handle": entity.get("handle"),
            "roles": entity.get(
                "roles",
                [],
            ),
        })

    return result