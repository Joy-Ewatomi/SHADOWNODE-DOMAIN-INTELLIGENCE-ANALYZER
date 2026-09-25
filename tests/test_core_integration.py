from analyzer import core


def test_analyze_domain_builds_complete_evidence_pipeline(monkeypatch):
    domain = "example.com"

    fake_rdap = {
        "available": True,
        "lookup_status": "success",
        "handle": "EXAMPLE",
        "ldh_name": "example.com",
        "unicode_name": "example.com",
        "status": ["active"],
        "nameservers": ["ns1.example.com"],
        "events": [],
        "entities": [],
    }

    fake_dns = {
        "a": {
            "records": ["192.0.2.10"],
            "status": "success",
        },
        "aaaa": {
            "records": [],
            "status": "no_answer",
        },
        "mx": {
            "records": ["mail.example.com."],
            "status": "success",
        },
        "ns": {
            "records": ["ns1.example.com."],
            "status": "success",
        },
        "txt": {
            "records": ["v=spf1 -all"],
            "status": "success",
        },
        "cname": {
            "records": [],
            "status": "no_answer",
        },
        "soa": {
            "records": ["ns1.example.com."],
            "status": "success",
        },
        "caa": {
            "records": [],
            "status": "no_answer",
        },
    }

    fake_ip = {
        "domain": domain,
        "ipv4": ["192.0.2.10"],
        "ipv6": [],
        "reverse_dns": {
            "192.0.2.10": {
                "hostname": "host.example.com",
                "status": "success",
            }
        },
        "status": "success",
    }

    fake_asn = {
        "192.0.2.10": {
            "ip": "192.0.2.10",
            "status": "success",
            "asn": "64500",
            "asn_cidr": "192.0.2.0/24",
            "asn_country_code": "ZZ",
            "asn_registry": "test",
            "asn_description": "TEST-NETWORK",
            "network": {
                "cidr": "192.0.2.0/24",
                "name": "TEST-NETWORK",
                "handle": "TEST-192-0-2",
            },
        }
    }

    fake_http = {
        "reachable": True,
        "status": "success",
        "initial_url": "https://example.com",
        "final_url": "https://example.com/",
        "status_code": 200,
        "reason": "OK",
        "redirects": [],
        "headers": {
            "server": "example",
        },
        "security_headers": {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": None,
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin",
            "permissions-policy": None,
        },
        "server": "example",
        "content_type": "text/html",
    }

    fake_tls = {
        "reachable": True,
        "status": "success",
        "hostname": domain,
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": {
            "name": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3",
            "bits": 256,
        },
        "certificate": {
            "subject": {
                "commonName": "example.com",
            },
            "issuer": {
                "commonName": "Example CA",
            },
            "serial_number": "123456",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "days_remaining": 99,
            "expired": False,
            "san": [
                "example.com",
            ],
        },
    }

    fake_ct = {
        "available": True,
        "status": "success",
        "query": domain,
        "certificates": [
            {
                "id": "cert-1",
                "tbs_sha256": "abc",
                "cert_sha256": "def",
                "pubkey_sha256": "ghi",
                "dns_names": [
                    "example.com",
                ],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
        ],
        "names": [
            "example.com",
        ],
        "certificate_count": 1,
    }

    monkeypatch.setattr(
        core,
        "get_rdap_info",
        lambda value: fake_rdap,
    )

    monkeypatch.setattr(
        core,
        "get_dns_records",
        lambda value: fake_dns,
    )

    monkeypatch.setattr(
        core,
        "get_ip_info",
        lambda value: fake_ip,
    )

    monkeypatch.setattr(
        core,
        "get_asn_info",
        lambda value: fake_asn,
    )

    monkeypatch.setattr(
        core,
        "analyze_http",
        lambda value: fake_http,
    )

    monkeypatch.setattr(
        core,
        "analyze_tls",
        lambda value: fake_tls,
    )

    monkeypatch.setattr(
        core,
        "get_ct_info",
        lambda value: fake_ct,
    )

    monkeypatch.setattr(
        core,
        "correlate_ct_with_dns",
        lambda value: [],
    )

    monkeypatch.setattr(
        core,
        "build_ct_infrastructure_correlations",
        lambda value: {
            "shared_ip": {},
            "shared_asn": {},
        },
    )

    monkeypatch.setattr(
        core,
        "build_ct_infrastructure_findings",
        lambda value: [],
    )

    report = core.analyze_domain(domain)

    assert report["domain"] == domain

    assert report["rdap"] == fake_rdap
    assert report["dns"] == fake_dns
    assert report["ip"] == fake_ip
    assert report["asn"] == fake_asn
    assert report["http"] == fake_http
    assert report["tls"] == fake_tls
    assert report["ct"] == fake_ct

    # Investigation metadata.
    assert report["case_id"] == "domain-example-com"
    assert report["run_id"]
    assert report["run_id"].startswith("run-")

    assert report["tool"] == "Domain Analyzer"
    assert report["tool_version"] == "0.1.0"

    assert report["collection_started_at"]
    assert report["collection_completed_at"]

    assert (
        report["collection_started_at"]
        <= report["collection_completed_at"]
    )

    assert report["collector_versions"] == {
        "RDAP Collector": "1.0",
        "DNS Collector": "1.0",
        "IP Collector": "1.0",
        "ASN Collector": "1.0",
        "HTTP Collector": "1.0",
        "TLS Collector": "1.0",
        "CT Collector": "1.0",
        "CT Correlation Engine": "1.0",
    }

    assert isinstance(
        report["evidence"],
        list,
    )

    assert len(report["evidence"]) == 8

    artifact_ids = [
        artifact["artifact_id"]
        for artifact in report["evidence"]
    ]

    assert len(artifact_ids) == len(set(artifact_ids))

    assert all(
        artifact["sha256"]
        for artifact in report["evidence"]
    )

    assert all(
        artifact["collected_at"]
        for artifact in report["evidence"]
    )

    manifest = report["evidence_manifest"]

    assert manifest["case_id"] == "domain-example-com"
    assert manifest["run_id"] == report["run_id"]

    assert manifest["sealed"] is True
    assert manifest["finalized_at"]
    assert manifest["sha256"]

    assert manifest["artifact_count"] == 8
    assert len(manifest["artifacts"]) == 8

    findings = report["findings"]

    assert isinstance(findings, list)

    finding_ids = [
        finding["finding_id"]
        for finding in findings
    ]

    assert len(finding_ids) == len(set(finding_ids))

    assert all(
    finding_id.startswith(
        f"{report['run_id']}-finding-"
    )
    for finding_id in finding_ids
)

    assert all(
        finding["evidence_artifacts"]
        for finding in findings
    )

    assert all(
        artifact_id in artifact_ids
        for finding in findings
        for artifact_id in finding["evidence_artifacts"]
    )


def test_analyze_domain_normalizes_domain(monkeypatch):
    observed_domains = []

    monkeypatch.setattr(
        core,
        "get_rdap_info",
        lambda value: (
            observed_domains.append(value)
            or {"available": False}
        ),
    )

    monkeypatch.setattr(
        core,
        "get_dns_records",
        lambda value: (
            observed_domains.append(value)
            or {}
        ),
    )

    monkeypatch.setattr(
        core,
        "get_ip_info",
        lambda value: (
            observed_domains.append(value)
            or {
                "ipv4": [],
                "ipv6": [],
            }
        ),
    )

    monkeypatch.setattr(
        core,
        "get_asn_info",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "analyze_http",
        lambda value: (
            observed_domains.append(value)
            or {}
        ),
    )

    monkeypatch.setattr(
        core,
        "analyze_tls",
        lambda value: (
            observed_domains.append(value)
            or {}
        ),
    )

    monkeypatch.setattr(
        core,
        "get_ct_info",
        lambda value: (
            observed_domains.append(value)
            or {"available": False}
        ),
    )

    monkeypatch.setattr(
        core,
        "correlate_ct_with_dns",
        lambda value: [],
    )

    monkeypatch.setattr(
        core,
        "build_ct_infrastructure_correlations",
        lambda value: {
            "shared_ip": {},
            "shared_asn": {},
        },
    )

    monkeypatch.setattr(
        core,
        "build_ct_infrastructure_findings",
        lambda value: [],
    )

    report = core.analyze_domain(
        "  Example.COM.  "
    )

    assert report["domain"] == "example.com"

    assert observed_domains == [
        "example.com",
        "example.com",
        "example.com",
        "example.com",
        "example.com",
        "example.com",
    ]


def test_analyze_domain_generates_unique_run_ids(monkeypatch):
    domain = "example.com"

    monkeypatch.setattr(
        core,
        "get_rdap_info",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "get_dns_records",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "get_ip_info",
        lambda value: {
            "ipv4": [],
            "ipv6": [],
        },
    )

    monkeypatch.setattr(
        core,
        "get_asn_info",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "analyze_http",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "analyze_tls",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "get_ct_info",
        lambda value: {},
    )

    monkeypatch.setattr(
        core,
        "correlate_ct_with_dns",
        lambda value: [],
    )

    monkeypatch.setattr(
        core,
        "build_ct_infrastructure_correlations",
        lambda value: {
            "shared_ip": {},
            "shared_asn": {},
        },
    )

    monkeypatch.setattr(
        core,
        "build_ct_infrastructure_findings",
        lambda value: [],
    )

    first = core.analyze_domain(domain)
    second = core.analyze_domain(domain)

    assert first["case_id"] == second["case_id"]
    assert first["case_id"] == "domain-example-com"

    assert first["run_id"] != second["run_id"]

    assert first["run_id"].startswith("run-")
    assert second["run_id"].startswith("run-")

    first_artifact_ids = [
        artifact["artifact_id"]
        for artifact in first["evidence"]
    ]

    second_artifact_ids = [
        artifact["artifact_id"]
        for artifact in second["evidence"]
    ]

    assert set(first_artifact_ids).isdisjoint(
        second_artifact_ids
    )

    first_finding_ids = [
        finding["finding_id"]
        for finding in first["findings"]
    ]

    second_finding_ids = [
        finding["finding_id"]
        for finding in second["findings"]
    ]

    assert set(first_finding_ids).isdisjoint(
        second_finding_ids
    )
