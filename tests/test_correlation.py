from analyzer.intelligence.correlation import (
    build_correlation_findings,
)


def test_single_ip_does_not_create_shared_asn_finding():
    findings = build_correlation_findings(
        domain="example.com",
        dns={},
        ip={
            "ipv4": ["192.0.2.10"],
            "ipv6": [],
        },
        asn={
            "192.0.2.10": {
                "asn": "64500",
                "asn_description": "Example Network",
                "network": {
                    "cidr": "192.0.2.0/24",
                    "name": "Example Network",
                    "handle": "EXAMPLE",
                },
            },
        },
        http={},
    )

    shared_asn_findings = [
        finding
        for finding in findings
        if finding["name"] == (
            "Observed IPs share ASN: AS64500"
        )
    ]

    assert shared_asn_findings == []
