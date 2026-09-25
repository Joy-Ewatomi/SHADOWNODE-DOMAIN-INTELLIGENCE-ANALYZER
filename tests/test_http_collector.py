import requests

from analyzer.collectors import http


class CaseInsensitiveHeaders(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get(self, key, default=None):
        key_lower = key.lower()

        for existing_key, value in self.items():
            if existing_key.lower() == key_lower:
                return value

        return default

    def items(self):
        return super().items()


class FakeResponse:
    def __init__(
        self,
        url="https://example.com/",
        status_code=200,
        reason="OK",
        headers=None,
        history=None,
    ):
        self.url = url
        self.status_code = status_code
        self.reason = reason
        self.headers = CaseInsensitiveHeaders(
            headers or {}
        )
        self.history = history or []


def test_analyze_http_success_and_security_headers(
    monkeypatch,
):
    response = FakeResponse(
        url="https://example.com/",
        status_code=200,
        reason="OK",
        headers={
            "Server": "ExampleServer",
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        },
    )

    def fake_get(*args, **kwargs):
        return response

    monkeypatch.setattr(
        http.requests,
        "get",
        fake_get,
    )

    result = http.analyze_http(
        "Example.COM."
    )

    assert result["reachable"] is True
    assert result["status"] == "success"
    assert result["initial_url"] == (
        "https://example.com."
    )
    assert result["final_url"] == (
        "https://example.com/"
    )
    assert result["status_code"] == 200
    assert result["reason"] == "OK"
    assert result["server"] == "ExampleServer"
    assert result["content_type"] == "text/html"

    assert result["security_headers"] == {
        "strict-transport-security": (
            "max-age=31536000"
        ),
        "content-security-policy": (
            "default-src 'self'"
        ),
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin",
        "permissions-policy": "camera=()",
    }


def test_analyze_http_filters_sensitive_headers(
    monkeypatch,
):
    response = FakeResponse(
        headers={
            "Server": "ExampleServer",
            "Set-Cookie": "session=secret",
            "Cookie": "session=secret",
            "Authorization": "Bearer secret",
            "Proxy-Authorization": "secret",
            "X-Test": "visible",
        },
    )

    monkeypatch.setattr(
        http.requests,
        "get",
        lambda *args, **kwargs: response,
    )

    result = http.analyze_http(
        "example.com"
    )

    assert "server" in result["headers"]
    assert "x-test" in result["headers"]

    assert "set-cookie" not in result["headers"]
    assert "cookie" not in result["headers"]
    assert "authorization" not in result["headers"]
    assert "proxy-authorization" not in result["headers"]


def test_analyze_http_records_redirects(
    monkeypatch,
):
    redirect_one = FakeResponse(
        url="https://example.com",
        status_code=301,
        reason="Moved Permanently",
        headers={
            "Location": "https://www.example.com"
        },
    )

    redirect_two = FakeResponse(
        url="https://www.example.com",
        status_code=302,
        reason="Found",
        headers={
            "Location": "https://www.example.com/"
        },
    )

    final = FakeResponse(
        url="https://www.example.com/",
        status_code=200,
        reason="OK",
        headers={
            "Content-Type": "text/html"
        },
        history=[
            redirect_one,
            redirect_two,
        ],
    )

    monkeypatch.setattr(
        http.requests,
        "get",
        lambda *args, **kwargs: final,
    )

    result = http.analyze_http(
        "example.com"
    )

    assert result["status"] == "success"
    assert result["final_url"] == (
        "https://www.example.com/"
    )

    assert result["redirects"] == [
        {
            "status_code": 301,
            "url": "https://example.com",
            "location": (
                "https://www.example.com"
            ),
        },
        {
            "status_code": 302,
            "url": "https://www.example.com",
            "location": (
                "https://www.example.com/"
            ),
        },
    ]


def test_analyze_http_http_error(
    monkeypatch,
):
    response = FakeResponse(
        status_code=403,
        reason="Forbidden",
        headers={
            "Server": "cloudflare",
            "Content-Type": "text/html",
        },
    )

    monkeypatch.setattr(
        http.requests,
        "get",
        lambda *args, **kwargs: response,
    )

    result = http.analyze_http(
        "example.com"
    )

    assert result["reachable"] is True
    assert result["status"] == "http_error"
    assert result["status_code"] == 403
    assert result["reason"] == "Forbidden"
    assert result["server"] == "cloudflare"


def test_analyze_http_timeout(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "request timed out"
        )

    monkeypatch.setattr(
        http.requests,
        "get",
        fake_get,
    )

    result = http.analyze_http(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "timeout"
    assert result["error_type"] == "timeout"
    assert result["error"] == (
        "request timed out"
    )


def test_analyze_http_tls_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.SSLError(
            "certificate verification failed"
        )

    monkeypatch.setattr(
        http.requests,
        "get",
        fake_get,
    )

    result = http.analyze_http(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "tls_error"
    assert result["error_type"] == "tls_error"
    assert result["error"] == (
        "certificate verification failed"
    )


def test_analyze_http_connection_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError(
            "connection refused"
        )

    monkeypatch.setattr(
        http.requests,
        "get",
        fake_get,
    )

    result = http.analyze_http(
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


def test_analyze_http_request_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.RequestException(
            "request failed"
        )

    monkeypatch.setattr(
        http.requests,
        "get",
        fake_get,
    )

    result = http.analyze_http(
        "example.com"
    )

    assert result["reachable"] is False
    assert result["status"] == "request_error"
    assert result["error_type"] == "request_error"
    assert result["error"] == (
        "request failed"
    )


def test_analyze_http_passes_expected_request_options(
    monkeypatch,
):
    captured = {}

    def fake_get(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        return FakeResponse()

    monkeypatch.setattr(
        http.requests,
        "get",
        fake_get,
    )

    http.analyze_http(
        "Example.COM"
    )

    assert captured["args"] == (
        "https://example.com",
    )

    assert captured["kwargs"]["timeout"] == 10
    assert captured["kwargs"]["allow_redirects"] is True
    assert captured["kwargs"]["headers"] == {
        "User-Agent": "SDIA/0.1.0"
    }
