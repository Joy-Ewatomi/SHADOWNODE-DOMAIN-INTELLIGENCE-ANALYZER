import socket


def get_ip_info(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")

    result = {
        "domain": domain,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": {},
        "status": "no_answer",
    }

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for address in addresses:
            family = address[0]
            ip = address[4][0]

            if family == socket.AF_INET:
                if ip not in result["ipv4"]:
                    result["ipv4"].append(ip)

            elif family == socket.AF_INET6:
                if ip not in result["ipv6"]:
                    result["ipv6"].append(ip)

    except socket.gaierror as exc:
        result["status"] = "resolution_error"
        result["error"] = str(exc)
        return result

    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    all_ips = (
        result["ipv4"]
        + result["ipv6"]
    )

    if not all_ips:
        result["status"] = "no_answer"
        return result

    result["status"] = "success"

    for ip in all_ips:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["reverse_dns"][ip] = {
                "hostname": hostname,
                "status": "success",
            }

        except (
            socket.herror,
            socket.gaierror,
        ) as exc:
            result["reverse_dns"][ip] = {
                "hostname": None,
                "status": "no_answer",
                "error": str(exc),
            }

        except OSError as exc:
            result["reverse_dns"][ip] = {
                "hostname": None,
                "status": "error",
                "error": str(exc),
            }

    return result
