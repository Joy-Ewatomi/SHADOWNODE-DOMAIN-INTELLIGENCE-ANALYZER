import socket
import ssl
from datetime import datetime, timezone


def analyze_tls(domain: str, port: int = 443) -> dict:
    domain = domain.strip().lower()

    result = {
        "reachable": False,
        "status": "not_attempted",
        "hostname": domain,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "certificate": {
            "subject": {},
            "issuer": {},
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "expired": None,
            "san": [],
        },
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (domain, port),
            timeout=10,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain,
            ) as tls_socket:
                result["reachable"] = True
                result["status"] = "success"

                result["tls_version"] = tls_socket.version()

                cipher = tls_socket.cipher()
                if cipher:
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }

                certificate = tls_socket.getpeercert()

                result["certificate"]["subject"] = parse_name(
                    certificate.get("subject", [])
                )

                result["certificate"]["issuer"] = parse_name(
                    certificate.get("issuer", [])
                )

                result["certificate"]["serial_number"] = (
                    certificate.get("serialNumber")
                )

                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                result["certificate"]["not_before"] = (
                    convert_certificate_date(not_before)
                )

                result["certificate"]["not_after"] = (
                    convert_certificate_date(not_after)
                )

                result["certificate"]["days_remaining"] = (
                    calculate_days_remaining(not_after)
                )

                days_remaining = (
                    result["certificate"]["days_remaining"]
                )

                result["certificate"]["expired"] = (
                    days_remaining is not None
                    and days_remaining < 0
                )

                san = certificate.get("subjectAltName", [])

                result["certificate"]["san"] = [
                    value
                    for key, value in san
                    if key == "DNS"
                ]

    except socket.timeout as exc:
        result["status"] = "timeout"
        result["error_type"] = "timeout"
        result["error"] = str(exc)

    except socket.gaierror as exc:
        result["status"] = "dns_error"
        result["error_type"] = "dns_error"
        result["error"] = str(exc)

    except ssl.SSLCertVerificationError as exc:
        result["status"] = "certificate_error"
        result["error_type"] = "certificate_error"
        result["error"] = str(exc)

    except ssl.SSLError as exc:
        result["status"] = "tls_error"
        result["error_type"] = "tls_error"
        result["error"] = str(exc)

    except ConnectionError as exc:
        result["status"] = "connection_error"
        result["error_type"] = "connection_error"
        result["error"] = str(exc)

    except OSError as exc:
        result["status"] = "connection_error"
        result["error_type"] = "connection_error"
        result["error"] = str(exc)

    except Exception as exc:
        result["status"] = "error"
        result["error_type"] = "error"
        result["error"] = str(exc)

    return result


def parse_name(name):
    result = {}

    for section in name:
        for key, value in section:
            result[key] = value

    return result


def convert_certificate_date(value):
    if not value:
        return None

    try:
        dt = datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z",
        )

        return dt.replace(
            tzinfo=timezone.utc
        ).isoformat()

    except ValueError:
        return value


def calculate_days_remaining(value):
    if not value:
        return None

    try:
        expires = datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z",
        ).replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        return (expires - now).days

    except ValueError:
        return None