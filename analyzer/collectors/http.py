import requests


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


SENSITIVE_HEADERS = {
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
}


def analyze_http(domain: str) -> dict:
    domain = domain.strip().lower()

    result = {
        "reachable": False,
        "status": "not_attempted",
        "initial_url": f"https://{domain}",
        "final_url": None,
        "status_code": None,
        "reason": None,
        "redirects": [],
        "headers": {},
        "security_headers": {},
        "server": None,
        "content_type": None,
    }

    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "DomainAnalyzer/1.0",
            },
        )

        result["reachable"] = True
        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["reason"] = response.reason

        if 200 <= response.status_code < 400:
            result["status"] = "success"
        else:
            result["status"] = "http_error"

        result["server"] = response.headers.get(
            "Server"
        )

        result["content_type"] = response.headers.get(
            "Content-Type"
        )

        for history_response in response.history:
            result["redirects"].append({
                "status_code": history_response.status_code,
                "url": history_response.url,
                "location": (
                    history_response.headers.get(
                        "Location"
                    )
                ),
            })

        for key, value in response.headers.items():
            key_lower = key.lower()

            if key_lower in SENSITIVE_HEADERS:
                continue

            result["headers"][key_lower] = value

        for header in SECURITY_HEADERS:
            result["security_headers"][header] = (
                response.headers.get(header)
            )

    except requests.exceptions.Timeout as exc:
        result["status"] = "timeout"
        result["error_type"] = "timeout"
        result["error"] = str(exc)

    except requests.exceptions.SSLError as exc:
        result["status"] = "tls_error"
        result["error_type"] = "tls_error"
        result["error"] = str(exc)

    except requests.exceptions.ConnectionError as exc:
        result["status"] = "connection_error"
        result["error_type"] = "connection_error"
        result["error"] = str(exc)

    except requests.exceptions.RequestException as exc:
        result["status"] = "request_error"
        result["error_type"] = "request_error"
        result["error"] = str(exc)

    return result
