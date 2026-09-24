import requests


CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
)


def get_ct_info(domain: str) -> dict:
    domain = domain.strip().lower()

    result = {
        "available": False,
        "status": "not_attempted",
        "query": domain,
        "certificates": [],
        "names": [],
        "certificate_count": 0,
    }

    try:
        response = requests.get(
            CERTSPOTTER_URL,
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=20,
            headers={
                "User-Agent": "DomainAnalyzer/1.0",
                "Accept": "application/json",
            },
        )

        if response.status_code >= 400:
            result["status"] = "http_error"
            result["error_type"] = "http_error"
            result["status_code"] = response.status_code
            result["reason"] = response.reason
            return result

        try:
            data = response.json()
        except ValueError as exc:
            result["status"] = "invalid_json"
            result["error_type"] = "invalid_json"
            result["error"] = str(exc)
            return result

        if not isinstance(data, list):
            result["status"] = "unexpected_format"
            result["error_type"] = "unexpected_format"
            result["error"] = (
                "Expected CT API response to be a list"
            )
            return result

        result["available"] = True
        result["status"] = "success"

        seen_certificates = set()
        seen_names = set()

        for certificate in data:
            if not isinstance(certificate, dict):
                continue

            certificate_id = certificate.get("id")

            if certificate_id is not None:
                certificate_id = str(
                    certificate_id
                )

            if (
                certificate_id
                and certificate_id in seen_certificates
            ):
                continue

            if certificate_id:
                seen_certificates.add(
                    certificate_id
                )

            dns_names = certificate.get(
                "dns_names",
                [],
            )

            if not isinstance(dns_names, list):
                dns_names = []

            normalized_names = []

            for name in dns_names:
                if not isinstance(name, str):
                    continue

                name = name.strip().lower()

                if not name:
                    continue

                normalized_names.append(name)

                if name not in seen_names:
                    seen_names.add(name)
                    result["names"].append(name)

            result["certificates"].append({
                "id": certificate_id,
                "tbs_sha256": certificate.get(
                    "tbs_sha256"
                ),
                "cert_sha256": certificate.get(
                    "cert_sha256"
                ),
                "pubkey_sha256": certificate.get(
                    "pubkey_sha256"
                ),
                "dns_names": normalized_names,
                "not_before": certificate.get(
                    "not_before"
                ),
                "not_after": certificate.get(
                    "not_after"
                ),
                "revoked": certificate.get(
                    "revoked"
                ),
            })

        result["certificate_count"] = len(
            result["certificates"]
        )

        result["names"].sort()

        return result

    except requests.exceptions.Timeout as exc:
        result["status"] = "timeout"
        result["error_type"] = "timeout"
        result["error"] = str(exc)

    except requests.exceptions.ConnectionError as exc:
        result["status"] = "connection_error"
        result["error_type"] = "connection_error"
        result["error"] = str(exc)

    except requests.exceptions.RequestException as exc:
        result["status"] = "request_error"
        result["error_type"] = "request_error"
        result["error"] = str(exc)

    except Exception as exc:
        result["status"] = "error"
        result["error_type"] = "error"
        result["error"] = str(exc)

    return result


def normalize_ct_hostname(
    name: str,
) -> str | None:
    name = name.strip().lower().rstrip(".")

    if not name:
        return None

    if name.startswith("*."):
        name = name[2:]

    return name or None