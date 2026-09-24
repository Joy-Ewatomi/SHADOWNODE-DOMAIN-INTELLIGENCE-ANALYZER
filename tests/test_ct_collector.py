import requests

from analyzer.collectors import ct


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        reason="OK",
        data=None,
        json_error=None,
    ):
        self.status_code = status_code
        self.reason = reason
        self._data = data
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise ValueError(self._json_error)

        return self._data


def test_get_ct_info_success_and_normalization(
    monkeypatch,
):
    data = [
        {
            "id": 123,
            "tbs_sha256": "tbs-1",
            "cert_sha256": "cert-1",
            "pubkey_sha256": "pubkey-1",
            "dns_names": [
                "Example.COM",
                "*.api.Example.COM",
                "www.example.com.",
                "Example.COM",
            ],
            "not_before": "2026-09-01T00:00:00Z",
            "not_after": "2026-12-01T00:00:00Z",
            "revoked": False,
        },
        {
            "id": "456",
            "tbs_sha256": "tbs-2",
            "cert_sha256": "cert-2",
            "pubkey_sha256": "pubkey-2",
            "dns_names": [
                "mail.example.com",
                "*.API.example.com",
            ],
            "not_before": "2026-09-02T00:00:00Z",
            "not_after": "2026-12-02T00:00:00Z",
            "revoked": False,
        },
    ]

    captured = {}

    def fake_get(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        return FakeResponse(
            data=data
        )

    monkeypatch.setattr(
        ct.requests,
        "get",
        fake_get,
    )

    result = ct.get_ct_info(
        "Example.COM."
    )

    assert result["available"] is True
    assert result["status"] == "success"
    assert result["query"] == "example.com."

    assert result["certificate_count"] == 2

    assert result["names"] == [
        "*.api.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com.",
    ]


def test_get_ct_info_deduplicates_certificate_ids(
    monkeypatch,
):
    data = [
        {
            "id": "same-id",
            "dns_names": [
                "example.com",
            ],
        },
        {
            "id": "same-id",
            "dns_names": [
                "other.example.com",
            ],
        },
        {
            "id": "different-id",
            "dns_names": [
                "third.example.com",
            ],
        },
    ]

    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data=data
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["certificate_count"] == 2

    assert result["certificates"] == [
        {
            "id": "same-id",
            "tbs_sha256": None,
            "cert_sha256": None,
            "pubkey_sha256": None,
            "dns_names": [
                "example.com"
            ],
            "not_before": None,
            "not_after": None,
            "revoked": None,
        },
        {
            "id": "different-id",
            "tbs_sha256": None,
            "cert_sha256": None,
            "pubkey_sha256": None,
            "dns_names": [
                "third.example.com"
            ],
            "not_before": None,
            "not_after": None,
            "revoked": None,
        },
    ]


def test_get_ct_info_skips_non_dict_certificates(
    monkeypatch,
):
    data = [
        "invalid",
        None,
        123,
        {
            "id": "valid",
            "dns_names": [
                "example.com",
            ],
        },
    ]

    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data=data
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["certificate_count"] == 1
    assert result["names"] == [
        "example.com"
    ]


def test_get_ct_info_skips_invalid_dns_names(
    monkeypatch,
):
    data = [
        {
            "id": "cert-1",
            "dns_names": [
                " Example.COM ",
                "",
                "   ",
                None,
                123,
                "*.API.example.com",
            ],
        },
    ]

    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data=data
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["certificates"][0][
        "dns_names"
    ] == [
        "example.com",
        "*.api.example.com",
    ]

    assert result["names"] == [
        "*.api.example.com",
        "example.com",
    ]


def test_get_ct_info_handles_non_list_dns_names(
    monkeypatch,
):
    data = [
        {
            "id": "cert-1",
            "dns_names": "example.com",
        },
    ]

    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data=data
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["certificate_count"] == 1
    assert result["certificates"][0][
        "dns_names"
    ] == []

    assert result["names"] == []


def test_get_ct_info_http_error(
    monkeypatch,
):
    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            status_code=429,
            reason="Too Many Requests",
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "http_error"
    assert result["error_type"] == "http_error"
    assert result["status_code"] == 429
    assert result["reason"] == (
        "Too Many Requests"
    )
    assert result["certificates"] == []
    assert result["names"] == []
    assert result["certificate_count"] == 0


def test_get_ct_info_invalid_json(
    monkeypatch,
):
    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            status_code=200,
            json_error="invalid JSON",
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "invalid_json"
    assert result["error_type"] == "invalid_json"
    assert result["error"] == "invalid JSON"


def test_get_ct_info_unexpected_format(
    monkeypatch,
):
    monkeypatch.setattr(
        ct.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data={
                "certificates": []
            }
        ),
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "unexpected_format"
    assert result["error_type"] == (
        "unexpected_format"
    )


def test_get_ct_info_timeout(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "CT request timed out"
        )

    monkeypatch.setattr(
        ct.requests,
        "get",
        fake_get,
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "timeout"
    assert result["error_type"] == "timeout"
    assert result["error"] == (
        "CT request timed out"
    )


def test_get_ct_info_connection_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError(
            "CT connection failed"
        )

    monkeypatch.setattr(
        ct.requests,
        "get",
        fake_get,
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "connection_error"
    assert result["error_type"] == (
        "connection_error"
    )
    assert result["error"] == (
        "CT connection failed"
    )


def test_get_ct_info_request_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.RequestException(
            "CT request failed"
        )

    monkeypatch.setattr(
        ct.requests,
        "get",
        fake_get,
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "request_error"
    assert result["error_type"] == (
        "request_error"
    )
    assert result["error"] == (
        "CT request failed"
    )


def test_get_ct_info_unexpected_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise RuntimeError(
            "unexpected CT failure"
        )

    monkeypatch.setattr(
        ct.requests,
        "get",
        fake_get,
    )

    result = ct.get_ct_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["status"] == "error"
    assert result["error_type"] == "error"
    assert result["error"] == (
        "unexpected CT failure"
    )


def test_get_ct_info_request_parameters(
    monkeypatch,
):
    captured = {}

    def fake_get(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        return FakeResponse(
            data=[]
        )

    monkeypatch.setattr(
        ct.requests,
        "get",
        fake_get,
    )

    ct.get_ct_info(
        "Example.COM"
    )

    assert captured["args"] == (
        ct.CERTSPOTTER_URL,
    )

    assert captured["kwargs"]["params"] == {
        "domain": "example.com",
        "include_subdomains": "true",
        "expand": "dns_names",
    }

    assert captured["kwargs"]["timeout"] == 20

    assert captured["kwargs"]["headers"] == {
        "User-Agent": "DomainAnalyzer/1.0",
        "Accept": "application/json",
    }


def test_normalize_ct_hostname_plain_name(
):
    assert ct.normalize_ct_hostname(
        "Example.COM."
    ) == "example.com"


def test_normalize_ct_hostname_wildcard(
):
    assert ct.normalize_ct_hostname(
        "*.API.Example.COM."
    ) == "api.example.com"


def test_normalize_ct_hostname_empty(
):
    assert ct.normalize_ct_hostname(
        ""
    ) is None


def test_normalize_ct_hostname_whitespace(
):
    assert ct.normalize_ct_hostname(
        "   "
    ) is None
