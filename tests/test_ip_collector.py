import socket

from analyzer.collectors import ip


def test_get_ip_info_resolves_ipv4_and_ipv6(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2001:db8::10", 0, 0, 0),
            ),
        ]

    def fake_gethostbyaddr(address):
        return (
            "host.example.com",
            [],
            [address],
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    monkeypatch.setattr(
        ip.socket,
        "gethostbyaddr",
        fake_gethostbyaddr,
    )

    result = ip.get_ip_info(
        "Example.COM."
    )

    assert result["domain"] == "example.com"

    assert result["ipv4"] == [
        "203.0.113.10"
    ]

    assert result["ipv6"] == [
        "2001:db8::10"
    ]

    assert result["status"] == "success"

    assert result["reverse_dns"] == {
        "203.0.113.10": {
            "hostname": "host.example.com",
            "status": "success",
        },
        "2001:db8::10": {
            "hostname": "host.example.com",
            "status": "success",
        },
    }


def test_get_ip_info_deduplicates_addresses(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            ),
        ]

    def fake_gethostbyaddr(address):
        return (
            "host.example.com",
            [],
            [address],
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    monkeypatch.setattr(
        ip.socket,
        "gethostbyaddr",
        fake_gethostbyaddr,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["ipv4"] == [
        "203.0.113.10"
    ]

    assert len(result["reverse_dns"]) == 1


def test_get_ip_info_resolution_error(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        raise socket.gaierror(
            "name resolution failed"
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    result = ip.get_ip_info(
        "missing.example.com"
    )

    assert result["domain"] == (
        "missing.example.com"
    )

    assert result["ipv4"] == []
    assert result["ipv6"] == []
    assert result["reverse_dns"] == {}

    assert result["status"] == (
        "resolution_error"
    )

    assert result["error"] == (
        "name resolution failed"
    )


def test_get_ip_info_os_error(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        raise OSError(
            "resolver unavailable"
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["status"] == "error"
    assert result["error"] == (
        "resolver unavailable"
    )


def test_get_ip_info_no_addresses(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return []

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["ipv4"] == []
    assert result["ipv6"] == []
    assert result["reverse_dns"] == {}
    assert result["status"] == "no_answer"


def test_reverse_dns_no_answer(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            )
        ]

    def fake_gethostbyaddr(address):
        raise socket.herror(
            "unknown host"
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    monkeypatch.setattr(
        ip.socket,
        "gethostbyaddr",
        fake_gethostbyaddr,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["status"] == "success"

    assert result["reverse_dns"] == {
        "203.0.113.10": {
            "hostname": None,
            "status": "no_answer",
            "error": "unknown host",
        }
    }


def test_reverse_dns_gaierror_is_no_answer(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            )
        ]

    def fake_gethostbyaddr(address):
        raise socket.gaierror(
            "reverse lookup failed"
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    monkeypatch.setattr(
        ip.socket,
        "gethostbyaddr",
        fake_gethostbyaddr,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["reverse_dns"][
        "203.0.113.10"
    ] == {
        "hostname": None,
        "status": "no_answer",
        "error": "reverse lookup failed",
    }


def test_reverse_dns_os_error(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            )
        ]

    def fake_gethostbyaddr(address):
        raise OSError(
            "reverse resolver unavailable"
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    monkeypatch.setattr(
        ip.socket,
        "gethostbyaddr",
        fake_gethostbyaddr,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["reverse_dns"][
        "203.0.113.10"
    ] == {
        "hostname": None,
        "status": "error",
        "error": (
            "reverse resolver unavailable"
        ),
    }


def test_mixed_reverse_dns_results(
    monkeypatch,
):
    def fake_getaddrinfo(
        domain,
        port,
        family,
        socktype,
    ):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.10", 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("203.0.113.11", 0),
            ),
        ]

    def fake_gethostbyaddr(address):
        if address == "203.0.113.10":
            return (
                "one.example.com",
                [],
                [address],
            )

        raise socket.herror(
            "unknown host"
        )

    monkeypatch.setattr(
        ip.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    monkeypatch.setattr(
        ip.socket,
        "gethostbyaddr",
        fake_gethostbyaddr,
    )

    result = ip.get_ip_info(
        "example.com"
    )

    assert result["status"] == "success"

    assert result["reverse_dns"][
        "203.0.113.10"
    ] == {
        "hostname": "one.example.com",
        "status": "success",
    }

    assert result["reverse_dns"][
        "203.0.113.11"
    ]["status"] == "no_answer"
