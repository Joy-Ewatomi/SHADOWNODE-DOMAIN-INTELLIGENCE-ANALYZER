import dns.exception
import dns.resolver

from analyzer.collectors import dns


class FakeAnswer:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


def test_get_dns_records_success(monkeypatch):
    def fake_resolve(
        domain,
        record_type,
        lifetime,
    ):
        values = {
            "A": ["203.0.113.10"],
            "AAAA": ["2001:db8::10"],
            "MX": ["10 mail.example.com."],
        }

        return [
            FakeAnswer(value)
            for value in values.get(
                record_type,
                [],
            )
        ]

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.get_dns_records(
        "Example.COM."
    )

    assert result["a"] == {
        "records": ["203.0.113.10"],
        "status": "success",
    }

    assert result["aaaa"] == {
        "records": ["2001:db8::10"],
        "status": "success",
    }

    assert result["mx"] == {
        "records": ["10 mail.example.com."],
        "status": "success",
    }


def test_get_dns_records_distinguishes_no_answer(
    monkeypatch,
):
    def fake_resolve(
        domain,
        record_type,
        lifetime,
    ):
        if record_type == "A":
            return [FakeAnswer("203.0.113.10")]

        raise dns.dns.resolver.NoAnswer()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.get_dns_records(
        "example.com"
    )

    assert result["a"]["status"] == "success"
    assert result["a"]["records"] == [
        "203.0.113.10"
    ]

    assert result["mx"]["status"] == "no_answer"
    assert result["mx"]["records"] == []


def test_get_dns_records_detects_nxdomain(
    monkeypatch,
):
    def fake_resolve(
        domain,
        record_type,
        lifetime,
    ):
        raise dns.dns.resolver.NXDOMAIN()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.get_dns_records(
        "does-not-exist.example"
    )

    for record_type in dns.RECORD_TYPES:
        key = record_type.lower()

        assert result[key]["records"] == []
        assert result[key]["status"] == "nxdomain"


def test_get_dns_records_detects_timeout(
    monkeypatch,
):
    def fake_resolve(
        domain,
        record_type,
        lifetime,
    ):
        raise dns.dns.exception.Timeout()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.get_dns_records(
        "example.com"
    )

    for record_type in dns.RECORD_TYPES:
        key = record_type.lower()

        assert result[key]["records"] == []
        assert result[key]["status"] == "timeout"


def test_get_dns_records_detects_no_nameservers(
    monkeypatch,
):
    def fake_resolve(
        domain,
        record_type,
        lifetime,
    ):
        raise dns.dns.resolver.NoNameservers()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.get_dns_records(
        "example.com"
    )

    for record_type in dns.RECORD_TYPES:
        key = record_type.lower()

        assert result[key]["records"] == []
        assert (
            result[key]["status"]
            == "no_nameservers"
        )


def test_get_dns_records_preserves_unexpected_error(
    monkeypatch,
):
    def fake_resolve(
        domain,
        record_type,
        lifetime,
    ):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.get_dns_records(
        "example.com"
    )

    assert result["a"]["records"] == []
    assert result["a"]["status"] == "error"
    assert (
        result["a"]["error"]
        == "resolver exploded"
    )


def test_resolve_hostname_success(
    monkeypatch,
):
    def fake_resolve(
        hostname,
        record_type,
        lifetime,
    ):
        if record_type == "A":
            return [
                FakeAnswer("203.0.113.10"),
                FakeAnswer("203.0.113.11"),
            ]

        return [
            FakeAnswer("2001:db8::10")
        ]

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.resolve_hostname(
        "Example.COM."
    )

    assert result["hostname"] == "example.com"
    assert result["ipv4"] == [
        "203.0.113.10",
        "203.0.113.11",
    ]
    assert result["ipv6"] == [
        "2001:db8::10"
    ]
    assert result["status"] == "success"
    assert result["resolves"] is True


def test_resolve_hostname_no_answer(
    monkeypatch,
):
    def fake_resolve(
        hostname,
        record_type,
        lifetime,
    ):
        raise dns.dns.resolver.NoAnswer()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.resolve_hostname(
        "example.com"
    )

    assert result["ipv4"] == []
    assert result["ipv6"] == []
    assert result["status"] == "no_answer"
    assert result["resolves"] is False


def test_resolve_hostname_nxdomain(
    monkeypatch,
):
    def fake_resolve(
        hostname,
        record_type,
        lifetime,
    ):
        raise dns.dns.resolver.NXDOMAIN()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.resolve_hostname(
        "missing.example.com"
    )

    assert result["ipv4"] == []
    assert result["ipv6"] == []
    assert result["status"] == "nxdomain"
    assert result["resolves"] is False


def test_resolve_hostname_timeout(
    monkeypatch,
):
    def fake_resolve(
        hostname,
        record_type,
        lifetime,
    ):
        raise dns.dns.exception.Timeout()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.resolve_hostname(
        "example.com"
    )

    assert result["status"] == "timeout"
    assert result["resolves"] is False


def test_resolve_hostname_no_nameservers(
    monkeypatch,
):
    def fake_resolve(
        hostname,
        record_type,
        lifetime,
    ):
        raise dns.dns.resolver.NoNameservers()

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.resolve_hostname(
        "example.com"
    )

    assert result["status"] == "no_nameservers"
    assert result["resolves"] is False


def test_resolve_hostname_preserves_error_details(
    monkeypatch,
):
    def fake_resolve(
        hostname,
        record_type,
        lifetime,
    ):
        if record_type == "A":
            raise RuntimeError(
                "A lookup failed"
            )

        return [
            FakeAnswer("2001:db8::10")
        ]

    monkeypatch.setattr(
        dns.dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = dns.resolve_hostname(
        "example.com"
    )

    assert result["ipv4"] == []
    assert result["ipv6"] == [
        "2001:db8::10"
    ]
    assert result["status"] == "success"
    assert result["resolves"] is True

    assert result["errors"] == [
        {
            "record_type": "A",
            "error": "A lookup failed",
        }
    ]
