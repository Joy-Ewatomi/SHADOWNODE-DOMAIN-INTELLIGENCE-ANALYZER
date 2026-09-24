import requests

from analyzer.collectors import rdap


BOOTSTRAP_DATA = {
    "services": [
        [
            ["com"],
            [
                "https://rdap.verisign.com/com/v1",
            ],
        ],
    ],
}


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


def fake_rdap_get(
    rdap_data,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        return FakeResponse(
            data=rdap_data
        )

    return fake_get


def test_find_rdap_server_success():
    result = rdap.find_rdap_server(
        "example.com",
        BOOTSTRAP_DATA,
    )

    assert result == (
        "https://rdap.verisign.com/com/v1"
    )


def test_find_rdap_server_case_insensitive():
    data = {
        "services": [
            [
                ["COM"],
                [
                    "https://example-rdap.test",
                ],
            ],
        ],
    }

    result = rdap.find_rdap_server(
        "Example.COM",
        data,
    )

    assert result == (
        "https://example-rdap.test"
    )


def test_find_rdap_server_missing_tld():
    data = {
        "services": [
            [
                ["net"],
                [
                    "https://example-rdap.test",
                ],
            ],
        ],
    }

    result = rdap.find_rdap_server(
        "example.com",
        data,
    )

    assert result is None


def test_find_rdap_server_empty_url():
    data = {
        "services": [
            [
                ["com"],
                [],
            ],
        ],
    }

    result = rdap.find_rdap_server(
        "example.com",
        data,
    )

    assert result is None


def test_get_rdap_info_success(
    monkeypatch,
):
    data = {
        "handle": "123456789_DOMAIN_COM-VRSN",
        "ldhName": "EXAMPLE.COM",
        "unicodeName": "example.com",
        "status": [
            "client delete prohibited",
            "client transfer prohibited",
        ],
        "nameservers": [
            {
                "ldhName": "NS1.EXAMPLE.COM",
            },
            {
                "ldhName": "NS2.EXAMPLE.COM",
            },
        ],
        "events": [
            {
                "eventAction": "registration",
                "eventDate": "2020-01-01T00:00:00Z",
            },
            {
                "eventAction": "expiration",
                "eventDate": "2027-01-01T00:00:00Z",
            },
        ],
        "entities": [
            {
                "handle": "EXAMPLE-ENTITY",
                "roles": ["registrant"],
            },
        ],
    }

    captured = []

    def fake_get(url, *args, **kwargs):
        captured.append({
            "url": url,
            "args": args,
            "kwargs": kwargs,
        })

        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        return FakeResponse(
            data=data
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "Example.COM."
    )

    assert result["available"] is True
    assert result["lookup_status"] == "success"

    assert result["handle"] == (
        "123456789_DOMAIN_COM-VRSN"
    )

    assert result["ldh_name"] == "EXAMPLE.COM"

    assert result["unicode_name"] == (
        "example.com"
    )

    assert result["status"] == [
        "client delete prohibited",
        "client transfer prohibited",
    ]

    assert result["nameservers"] == [
        "NS1.EXAMPLE.COM",
        "NS2.EXAMPLE.COM",
    ]

    assert result["events"] == [
        {
            "event_action": "registration",
            "event_date": "2020-01-01T00:00:00Z",
        },
        {
            "event_action": "expiration",
            "event_date": "2027-01-01T00:00:00Z",
        },
    ]

    assert result["entities"] == [
        {
            "handle": "EXAMPLE-ENTITY",
            "roles": ["registrant"],
        },
    ]

    assert len(captured) == 2

    assert captured[0]["url"] == (
        rdap.RDAP_BOOTSTRAP_URL
    )

    assert captured[1]["url"].endswith(
        "/domain/example.com"
    )

    assert captured[1]["kwargs"]["timeout"] == 10

    assert captured[1]["kwargs"]["headers"] == {
        "Accept": (
            "application/rdap+json, "
            "application/json"
        ),
    }


def test_get_rdap_info_normalizes_domain(
    monkeypatch,
):
    captured = []

    def fake_get(url, *args, **kwargs):
        captured.append(url)

        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        return FakeResponse(
            data={}
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    rdap.get_rdap_info(
        "  Example.COM.  "
    )

    assert captured[0] == (
        rdap.RDAP_BOOTSTRAP_URL
    )

    assert captured[1].endswith(
        "/domain/example.com"
    )


def test_get_rdap_info_bootstrap_http_error(
    monkeypatch,
):
    monkeypatch.setattr(
        rdap.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            status_code=500,
            reason="Server Error",
        ),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "bootstrap_http_error"
    )
    assert result["status_code"] == 500
    assert result["reason"] == "Server Error"


def test_get_rdap_info_bootstrap_invalid_json(
    monkeypatch,
):
    monkeypatch.setattr(
        rdap.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            status_code=200,
            json_error="invalid JSON",
        ),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "bootstrap_invalid_json"
    )
    assert result["error"] == "invalid JSON"


def test_get_rdap_info_bootstrap_timeout(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "RDAP bootstrap timed out"
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "bootstrap_timeout"
    )
    assert result["error"] == (
        "RDAP bootstrap timed out"
    )


def test_get_rdap_info_bootstrap_connection_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError(
            "RDAP bootstrap connection failed"
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "bootstrap_connection_error"
    )
    assert result["error"] == (
        "RDAP bootstrap connection failed"
    )


def test_get_rdap_info_bootstrap_request_error(
    monkeypatch,
):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.RequestException(
            "RDAP bootstrap request failed"
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "bootstrap_request_error"
    )
    assert result["error"] == (
        "RDAP bootstrap request failed"
    )


def test_get_rdap_info_no_server(
    monkeypatch,
):
    data = {
        "services": [
            [
                ["net"],
                [
                    "https://rdap.example.net",
                ],
            ],
        ],
    }

    monkeypatch.setattr(
        rdap.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data=data
        ),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == "no_server"
    assert result["error"] == (
        "No RDAP server found"
    )


def test_get_rdap_info_not_found(
    monkeypatch,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        return FakeResponse(
            status_code=404,
            reason="Not Found",
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == "not_found"
    assert result["status_code"] == 404
    assert result["reason"] == "Not Found"
    assert result["error"] == (
        "Domain not found in RDAP"
    )


def test_get_rdap_info_registry_http_error(
    monkeypatch,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        return FakeResponse(
            status_code=500,
            reason="Server Error",
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == "http_error"
    assert result["status_code"] == 500
    assert result["reason"] == "Server Error"


def test_get_rdap_info_registry_invalid_json(
    monkeypatch,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        return FakeResponse(
            status_code=200,
            json_error="invalid registry JSON",
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "invalid_json"
    )
    assert result["error"] == (
        "invalid registry JSON"
    )


def test_get_rdap_info_registry_timeout(
    monkeypatch,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        raise requests.exceptions.Timeout(
            "RDAP registry timed out"
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == "timeout"
    assert result["error"] == (
        "RDAP registry timed out"
    )


def test_get_rdap_info_registry_connection_error(
    monkeypatch,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        raise requests.exceptions.ConnectionError(
            "RDAP registry connection failed"
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "connection_error"
    )
    assert result["error"] == (
        "RDAP registry connection failed"
    )


def test_get_rdap_info_registry_request_error(
    monkeypatch,
):
    def fake_get(url, *args, **kwargs):
        if url == rdap.RDAP_BOOTSTRAP_URL:
            return FakeResponse(
                data=BOOTSTRAP_DATA
            )

        raise requests.exceptions.RequestException(
            "RDAP registry request failed"
        )

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_get,
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == (
        "request_error"
    )
    assert result["error"] == (
        "RDAP registry request failed"
    )


def test_get_rdap_info_unexpected_bootstrap_format(
    monkeypatch,
):
    monkeypatch.setattr(
        rdap.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            data=[
                "unexpected",
                "format",
            ]
        ),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is False
    assert result["lookup_status"] == "error"


def test_get_rdap_info_preserves_registry_status(
    monkeypatch,
):
    data = {
        "handle": "EXAMPLE",
        "ldhName": "EXAMPLE.COM",
        "status": [
            "active",
            "client transfer prohibited",
        ],
    }

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_rdap_get(data),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is True
    assert result["lookup_status"] == "success"

    assert result["status"] == [
        "active",
        "client transfer prohibited",
    ]


def test_get_rdap_info_handles_missing_optional_fields(
    monkeypatch,
):
    data = {
        "handle": "EXAMPLE",
        "ldhName": "EXAMPLE.COM",
    }

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_rdap_get(data),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["available"] is True
    assert result["lookup_status"] == "success"
    assert result["handle"] == "EXAMPLE"
    assert result["ldh_name"] == "EXAMPLE.COM"
    assert result["unicode_name"] is None
    assert result["status"] == []
    assert result["nameservers"] == []
    assert result["events"] == []
    assert result["entities"] == []


def test_get_rdap_info_parse_nameservers(
    monkeypatch,
):
    data = {
        "nameservers": [
            {
                "ldhName": "NS1.EXAMPLE.COM",
            },
            {
                "ldhName": "NS2.EXAMPLE.COM",
            },
            {},
        ],
    }

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_rdap_get(data),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["nameservers"] == [
        "NS1.EXAMPLE.COM",
        "NS2.EXAMPLE.COM",
    ]


def test_get_rdap_info_parse_events(
    monkeypatch,
):
    data = {
        "events": [
            {
                "eventAction": "registration",
                "eventDate": "2020-01-01T00:00:00Z",
            },
            {
                "eventAction": "expiration",
                "eventDate": "2027-01-01T00:00:00Z",
            },
        ],
    }

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_rdap_get(data),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["events"] == [
        {
            "event_action": "registration",
            "event_date": "2020-01-01T00:00:00Z",
        },
        {
            "event_action": "expiration",
            "event_date": "2027-01-01T00:00:00Z",
        },
    ]


def test_get_rdap_info_parse_entities(
    monkeypatch,
):
    data = {
        "entities": [
            {
                "handle": "ENTITY-1",
                "roles": ["registrant"],
            },
            {
                "handle": "ENTITY-2",
            },
        ],
    }

    monkeypatch.setattr(
        rdap.requests,
        "get",
        fake_rdap_get(data),
    )

    result = rdap.get_rdap_info(
        "example.com"
    )

    assert result["entities"] == [
        {
            "handle": "ENTITY-1",
            "roles": ["registrant"],
        },
        {
            "handle": "ENTITY-2",
            "roles": [],
        },
    ]
