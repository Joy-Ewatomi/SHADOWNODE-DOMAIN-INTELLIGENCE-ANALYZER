from analyzer.intelligence.ct_correlation import (
    build_ct_infrastructure_correlations,
    build_ct_infrastructure_findings,
)


def test_shared_ip_correlation():
    ct_dns = [
        {
            "hostname": "api.example.com",
            "dns": {
                "ipv4": ["203.0.113.10"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.10": {
                    "asn": "64500",
                    "asn_description": "Example Network",
                }
            },
        },
        {
            "hostname": "mail.example.com",
            "dns": {
                "ipv4": ["203.0.113.10"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.10": {
                    "asn": "64500",
                    "asn_description": "Example Network",
                }
            },
        },
    ]

    result = build_ct_infrastructure_correlations(
        ct_dns
    )

    assert "203.0.113.10" in result["shared_ip"]

    assert result["shared_ip"]["203.0.113.10"] == {
        "ip": "203.0.113.10",
        "hostnames": [
            "api.example.com",
            "mail.example.com",
        ],
    }


def test_shared_asn_correlation():
    ct_dns = [
        {
            "hostname": "api.example.com",
            "dns": {
                "ipv4": ["203.0.113.10"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.10": {
                    "asn": "64500",
                    "asn_description": "Example Network",
                }
            },
        },
        {
            "hostname": "www.example.com",
            "dns": {
                "ipv4": ["203.0.113.20"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.20": {
                    "asn": "64500",
                    "asn_description": "Example Network",
                }
            },
        },
    ]

    result = build_ct_infrastructure_correlations(
        ct_dns
    )

    assert "64500" in result["shared_asn"]

    assert result["shared_asn"]["64500"] == {
        "asn": "64500",
        "hostnames": [
            "api.example.com",
            "www.example.com",
        ],
        "ips": [
            "203.0.113.10",
            "203.0.113.20",
        ],
        "descriptions": [
            "Example Network",
        ],
    }


def test_single_hostname_is_not_shared_ip_or_asn():
    ct_dns = [
        {
            "hostname": "api.example.com",
            "dns": {
                "ipv4": ["203.0.113.10"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.10": {
                    "asn": "64500",
                    "asn_description": "Example Network",
                }
            },
        }
    ]

    result = build_ct_infrastructure_correlations(
        ct_dns
    )

    assert result["shared_ip"] == {}
    assert result["shared_asn"] == {}


def test_shared_ip_finding_is_derived_correlation():
    infrastructure = {
        "shared_ip": {
            "203.0.113.10": {
                "ip": "203.0.113.10",
                "hostnames": [
                    "api.example.com",
                    "mail.example.com",
                ],
            }
        },
        "shared_asn": {},
    }

    findings = build_ct_infrastructure_findings(
        infrastructure
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["category"] == "correlation"
    assert (
        finding["name"]
        == "Shared IP infrastructure: 203.0.113.10"
    )
    assert finding["finding_type"] == "correlation"
    assert finding["confidence"] == "low"

    assert (
        finding["evidence"][0]["source"]
        == "CT Infrastructure Correlation"
    )

    assert (
        finding["evidence"][0]["record_type"]
        == "shared_ip"
    )
    assert (
        finding["evidence"][0]["classification"]
        == "derived"
    )
    assert (
        finding["evidence"][0]["confidence"]
        == "low"
    )


def test_shared_asn_finding_is_derived_correlation():
    infrastructure = {
        "shared_ip": {},
        "shared_asn": {
            "64500": {
                "asn": "64500",
                "hostnames": [
                    "api.example.com",
                    "www.example.com",
                ],
                "ips": [
                    "203.0.113.10",
                    "203.0.113.20",
                ],
                "descriptions": [
                    "Example Network",
                ],
            }
        },
    }

    findings = build_ct_infrastructure_findings(
        infrastructure
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["category"] == "correlation"
    assert (
        finding["name"]
        == "Shared ASN infrastructure: AS64500"
    )
    assert finding["finding_type"] == "correlation"
    assert finding["confidence"] == "low"

    assert (
        finding["evidence"][0]["source"]
        == "CT Infrastructure Correlation"
    )

    assert (
        finding["evidence"][0]["record_type"]
        == "shared_asn"
    )
    assert (
        finding["evidence"][0]["classification"]
        == "derived"
    )
    assert (
        finding["evidence"][0]["confidence"]
        == "low"
    )


def test_no_false_shared_infrastructure():
    ct_dns = [
        {
            "hostname": "one.example.com",
            "dns": {
                "ipv4": ["203.0.113.10"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.10": {
                    "asn": "64500",
                    "asn_description": "Network A",
                }
            },
        },
        {
            "hostname": "two.example.com",
            "dns": {
                "ipv4": ["203.0.113.20"],
                "ipv6": [],
            },
            "asn": {
                "203.0.113.20": {
                    "asn": "64501",
                    "asn_description": "Network B",
                }
            },
        },
    ]

    result = build_ct_infrastructure_correlations(
        ct_dns
    )

    assert result["shared_ip"] == {}
    assert result["shared_asn"] == {}
