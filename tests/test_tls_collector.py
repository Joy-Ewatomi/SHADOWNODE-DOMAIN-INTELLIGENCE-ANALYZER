import socket
import ssl
from datetime import datetime, timezone

from analyzer.collectors import tls


class FakeSocket:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.closed = True

    def sendall(self, data):
        pass


class FakeTLSSocket:
    def __init__(self, certificate):
        self.certificate = certificate
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.closed = True

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )

    def getpeercert(self):
        return self.certificate


class FakeSSLContext:
    def __init__(self, certificate):
        self.certificate = certificate
        self.server_hostname = None

    def wrap_socket(
        self,
        sock,
        server_hostname=None,
    ):
        self.server_hostname = server_hostname

        return FakeTLSSocket(
            self.certificate
        )


def test_analyze_tls_success(
    monkeypatch,
):
    certificate = {
        "subject": [
            (
                ("commonName", "example.com"),
            ),
            (
                ("organizationName", "Example Org"),
            ),
        ],
        "issuer": [
            (
                ("countryName", "US"),
            ),
            (
                ("organizationName", "Example CA"),
            ),
            (
                ("commonName", "Example Root"),
            ),
        ],
        "serialNumber": "ABC123",
        "notBefore": (
            "Sep 20 00:00:00 2026 GMT"
        ),
        "notAfter": (
            "Dec 19 23:59:59 2026 GMT"
        ),
        "subjectAltName": [
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
            ("IP Address", "192.0.2.10"),
        ],
    }

    fake_context = FakeSSLContext(
        certificate
    )

    monkeypatch.setattr(
        tls.ssl,
        "create_default_context",
        lambda: fake_context,
    )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        lambda address, timeout: FakeSocket(),
    )

    result = tls.analyze_tls(
        "Example.COM."
    )

    assert result["reachable"] is True
    assert result["status"] == "success"
    assert result["hostname"] == "example.com."
    assert result["port"] == 443

    assert result["tls_version"] == "TLSv1.3"

    assert result["cipher"] == {
        "name": "TLS_AES_256_GCM_SHA384",
        "protocol": "TLSv1.3",
        "bits": 256,
    }

    assert result["certificate"]["subject"] == {
        "commonName": "example.com",
        "organizationName": "Example Org",
    }

    assert result["certificate"]["issuer"] == {
        "countryName": "US",
        "organizationName": "Example CA",
        "commonName": "Example Root",
    }

    assert result["certificate"]["serial_number"] == (
        "ABC123"
    )

    assert result["certificate"]["not_before"] == (
        "2026-09-20T00:00:00+00:00"
    )

    assert result["certificate"]["not_after"] == (
        "2026-12-19T23:59:59+00:00"
    )

    assert result["certificate"]["days_remaining"] is not None
    assert result["certificate"]["expired"] is False

    assert result["certificate"]["san"] == [
        "example.com",
        "www.example.com",
    ]

    assert fake_context.server_hostname == (
        "example.com."
    )


def test_analyze_tls_custom_port(
    monkeypatch,
):
    captured = {}

    certificate = {
        "subject": [],
        "issuer": [],
        "serialNumber": None,
        "notBefore": None,
        "notAfter": None,
        "subjectAltName": [],
    }

    fake_context = FakeSSLContext(
        certificate
    )

    def fake_create_connection(
        address,
        timeout,
    ):
        captured["address"] = address
        captured["timeout"] = timeout

        return FakeSocket()

    monkeypatch.setattr(
        tls.ssl,
        "create_default_context",
        lambda: fake_context,
    )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_create_connection,
    )

    result = tls.analyze_tls(
        "example.com",
        port=8443,
    )

    assert result["status"] == "success"
    assert result["port"] == 8443
    assert captured["address"] == (
        "example.com",
        8443,
    )
    assert captured["timeout"] == 10


def test_analyze_tls_timeout(
    monkeypatch,
):
    def fake_create_connection(
        address,
        timeout,
    ):
        raise socket.timeout(
            "connection timed out"
        )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_create_connection,
    )

    result = tls.analyze_tls(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "timeout"
    assert result["error_type"] == "timeout"
    assert result["error"] == (
        "connection timed out"
    )


def test_analyze_tls_dns_error(
    monkeypatch,
):
    def fake_create_connection(
        address,
        timeout,
    ):
        raise socket.gaierror(
            "name resolution failed"
        )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_create_connection,
    )

    result = tls.analyze_tls(
        "missing.example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "dns_error"
    assert result["error_type"] == "dns_error"
    assert result["error"] == (
        "name resolution failed"
    )


def test_analyze_tls_certificate_error(
    monkeypatch,
):
    certificate_error = (
        ssl.SSLCertVerificationError(
            "certificate verify failed"
        )
    )

    def fake_wrap_socket(
        sock,
        server_hostname=None,
    ):
        raise certificate_error

    class FakeContext:
        def wrap_socket(
            self,
            sock,
            server_hostname=None,
        ):
            return fake_wrap_socket(
                sock,
                server_hostname,
            )

    monkeypatch.setattr(
        tls.ssl,
        "create_default_context",
        lambda: FakeContext(),
    )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        lambda address, timeout: FakeSocket(),
    )

    result = tls.analyze_tls(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "certificate_error"
    assert result["error_type"] == (
        "certificate_error"
    )


def test_analyze_tls_ssl_error(
    monkeypatch,
):
    def fake_wrap_socket(
        sock,
        server_hostname=None,
    ):
        raise ssl.SSLError(
            "TLS handshake failed"
        )

    class FakeContext:
        def wrap_socket(
            self,
            sock,
            server_hostname=None,
        ):
            return fake_wrap_socket(
                sock,
                server_hostname,
            )

    monkeypatch.setattr(
        tls.ssl,
        "create_default_context",
        lambda: FakeContext(),
    )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        lambda address, timeout: FakeSocket(),
    )

    result = tls.analyze_tls(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "tls_error"
    assert result["error_type"] == "tls_error"
    assert result["error"] == (
        "('TLS handshake failed',)"
    )


def test_analyze_tls_connection_error(
    monkeypatch,
):
    def fake_create_connection(
        address,
        timeout,
    ):
        raise ConnectionError(
            "connection refused"
        )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_create_connection,
    )

    result = tls.analyze_tls(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "connection_error"
    assert result["error_type"] == (
        "connection_error"
    )
    assert result["error"] == (
        "connection refused"
    )


def test_analyze_tls_os_error(
    monkeypatch,
):
    def fake_create_connection(
        address,
        timeout,
    ):
        raise OSError(
            "network unavailable"
        )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_create_connection,
    )

    result = tls.analyze_tls(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "connection_error"
    assert result["error_type"] == (
        "connection_error"
    )
    assert result["error"] == (
        "network unavailable"
    )


def test_analyze_tls_unexpected_error(
    monkeypatch,
):
    def fake_create_connection(
        address,
        timeout,
    ):
        raise RuntimeError(
            "unexpected failure"
        )

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_create_connection,
    )

    result = tls.analyze_tls(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "error"
    assert result["error_type"] == "error"
    assert result["error"] == (
        "unexpected failure"
    )


def test_parse_name(
):
    name = [
        (
            ("countryName", "US"),
            ("organizationName", "Example Org"),
        ),
        (
            ("commonName", "example.com"),
        ),
    ]

    assert tls.parse_name(name) == {
        "countryName": "US",
        "organizationName": "Example Org",
        "commonName": "example.com",
    }


def test_convert_certificate_date(
):
    value = "Sep 20 00:00:00 2026 GMT"

    assert tls.convert_certificate_date(
        value
    ) == "2026-09-20T00:00:00+00:00"


def test_convert_certificate_date_invalid_value(
):
    value = "not-a-certificate-date"

    assert tls.convert_certificate_date(
        value
    ) == value


def test_convert_certificate_date_empty_value(
):
    assert tls.convert_certificate_date(
        None
    ) is None


def test_calculate_days_remaining_empty_value(
):
    assert tls.calculate_days_remaining(
        None
    ) is None


def test_calculate_days_remaining_invalid_value(
):
    assert tls.calculate_days_remaining(
        "invalid"
    ) is None
