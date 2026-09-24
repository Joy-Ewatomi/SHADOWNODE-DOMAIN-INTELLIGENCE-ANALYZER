from analyzer.intelligence import ct_correlation


def test_correlate_ct_with_dns_preserves_certificate_metadata(
    monkeypatch,
):
    def fake_resolve_hostname(hostname):
        assert hostname == "api.example.com"

        return {
            "domain": hostname,
            "ipv4": ["203.0.113.10"],
            "ipv6": [],
            "status": "success",
        }

    def fake_get_asn_info(ips):
        assert ips == ["203.0.113.10"]

        return {
            "203.0.113.10": {
                "ip": "203.0.113.10",
                "status": "success",
                "asn": "64500",
                "asn_description": "Example Network",
            }
        }

    monkeypatch.setattr(
        ct_correlation,
        "resolve_hostname",
        fake_resolve_hostname,
    )

    monkeypatch.setattr(
        ct_correlation,
        "get_asn_info",
        fake_get_asn_info,
    )

    ct = {
        "available": True,
        "names": [
            "*.api.example.com",
            "api.example.com",
            "*.api.example.com",
        ],
    }

    result = ct_correlation.correlate_ct_with_dns(ct)

    assert len(result) == 1

    item = result[0]

    assert item["hostname"] == "api.example.com"

    assert item["certificate_names"] == [
        "*.api.example.com",
        "api.example.com",
    ]

    assert item["wildcard_certificate_names"] == [
        "*.api.example.com",
    ]

    assert item["exact_certificate_names"] == [
        "api.example.com",
    ]

    assert item["dns"]["ipv4"] == [
        "203.0.113.10",
    ]

    assert item["asn"]["203.0.113.10"]["asn"] == "64500"

    assert (
        item["observation"]["dns_source"]
        == "system DNS resolver"
    )

    assert (
        item["observation"]["asn_source"]
        == "IPWHOIS/RDAP"
    )

    assert (
        item["observation"]["method"]
        == "passive DNS and IP registration lookup"
    )

    assert item["observation"]["dns_observed_at"]
    assert item["observation"]["asn_observed_at"]

    assert item["asn_observations"] == {
        "203.0.113.10": {
            "observed_at": item["asn_observations"][
                "203.0.113.10"
            ]["observed_at"],
            "source": "IPWHOIS/RDAP",
            "method": "IP registration lookup",
        }
    }


def test_correlate_ct_with_dns_returns_empty_when_ct_unavailable():
    ct = {
        "available": False,
        "names": [
            "api.example.com",
        ],
    }

    result = ct_correlation.correlate_ct_with_dns(ct)

    assert result == []


def test_correlate_ct_with_dns_returns_empty_without_names():
    ct = {
        "available": True,
        "names": [],
    }

    result = ct_correlation.correlate_ct_with_dns(ct)

    assert result == []


def test_correlate_ct_with_dns_skips_invalid_names(
    monkeypatch,
):
    def fake_resolve_hostname(hostname):
        return {
            "domain": hostname,
            "ipv4": ["203.0.113.10"],
            "ipv6": [],
            "status": "success",
        }

    def fake_get_asn_info(ips):
        return {
            "203.0.113.10": {
                "ip": "203.0.113.10",
                "status": "success",
                "asn": "64500",
                "asn_description": "Example Network",
            }
        }

    monkeypatch.setattr(
        ct_correlation,
        "resolve_hostname",
        fake_resolve_hostname,
    )

    monkeypatch.setattr(
        ct_correlation,
        "get_asn_info",
        fake_get_asn_info,
    )

    ct = {
        "available": True,
        "names": [
            "*.api.example.com",
            "",
            None,
        ],
    }

    result = ct_correlation.correlate_ct_with_dns(ct)

    assert len(result) == 1
    assert result[0]["hostname"] == "api.example.com"
