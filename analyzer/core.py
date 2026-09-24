from .collectors.dns import get_dns_records
from .collectors.rdap import get_rdap_info
from .collectors.ip import get_ip_info
from .collectors.asn import get_asn_info
from .collectors.http import analyze_http
from .collectors.tls import analyze_tls
from .collectors.ct import get_ct_info
from datetime import datetime, timezone

from .models.report import DomainReport

from .evidence import EvidenceCollector

from .intelligence.findings import (
    build_findings,
    build_ct_findings,
)

from .intelligence.correlation import (
    build_correlation_findings,
)

from .intelligence.ct_correlation import (
    correlate_ct_with_dns,
    build_ct_infrastructure_correlations,
    build_ct_infrastructure_findings,
)

TOOL_NAME = "Domain Analyzer"
TOOL_VERSION = "1.0"

COLLECTOR_VERSIONS = {
    "RDAP Collector": "1.0",
    "DNS Collector": "1.0",
    "IP Collector": "1.0",
    "ASN Collector": "1.0",
    "HTTP Collector": "1.0",
    "TLS Collector": "1.0",
    "CT Collector": "1.0",
    "CT Correlation Engine": "1.0",
}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def link_findings_to_artifacts(
    findings: list[dict],
    artifact_ids: dict[str, str],
) -> list[dict]:
    """
    Link each finding to the preserved evidence artifacts
    that support it.

    The existing human-readable evidence remains embedded
    inside the finding. This function additionally records
    explicit artifact IDs so the finding can be traced back
    to hashed evidence.
    """

    source_to_artifact = {
    "DNS": artifact_ids.get("dns"),
    "IPWHOIS/RDAP": artifact_ids.get("asn"),
    "HTTP": artifact_ids.get("http"),
    "TLS": artifact_ids.get("tls"),
    "Cert Spotter": artifact_ids.get("ct"),
    "CT Infrastructure Correlation": (
        artifact_ids.get("ct_dns_correlation")
    ),
}

    for finding in findings:
        linked_artifacts = []

        for evidence in finding.get(
            "evidence",
            [],
        ):
            source = evidence.get("source")

            artifact_id = source_to_artifact.get(
                source
            )

            if (
                artifact_id
                and artifact_id not in linked_artifacts
            ):
                linked_artifacts.append(
                    artifact_id
                )

        finding["evidence_artifacts"] = (
            linked_artifacts
        )

    return findings


def assign_finding_ids(
    findings: list[dict],
    case_id: str,
) -> list[dict]:
    """
    Assign stable sequential IDs to findings within a case.

    Finding IDs are assigned after all finding builders have
    completed, so the identifier does not depend on which
    individual builder created the finding.
    """

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        finding["finding_id"] = (
            f"{case_id}-finding-{index:04d}"
        )

    return findings


def analyze_domain(domain: str) -> dict:
    collection_started_at = utc_now()

    domain = domain.strip().lower().rstrip(".")

    case_id = (
        f"domain-{domain.replace('.', '-')}"
    )

    evidence = EvidenceCollector(
        case_id=case_id,
        collector_version="1.0",
    )

    # ---------------------------------------------------------
    # RDAP
    # ---------------------------------------------------------

    rdap = get_rdap_info(domain)

    rdap_artifact = evidence.add(
        artifact_type="rdap_domain",
        source="IANA RDAP bootstrap + registry RDAP",
        data=rdap,
        collector="RDAP Collector",
    )

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------

    dns = get_dns_records(domain)

    dns_artifact = evidence.add(
        artifact_type="dns_records",
        source="system DNS resolver",
        data=dns,
        collector="DNS Collector",
    )

    # ---------------------------------------------------------
    # IP resolution
    # ---------------------------------------------------------

    ip = get_ip_info(domain)

    ip_artifact = evidence.add(
        artifact_type="ip_resolution",
        source="system socket resolver",
        data=ip,
        collector="IP Collector",
    )

    all_ips = (
        ip.get("ipv4", [])
        + ip.get("ipv6", [])
    )

    # ---------------------------------------------------------
    # ASN / IP registration
    # ---------------------------------------------------------

    asn = get_asn_info(all_ips)

    asn_artifact = evidence.add(
        artifact_type="ip_registration",
        source="IPWHOIS/RDAP",
        data=asn,
        collector="ASN Collector",
    )

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    http = analyze_http(domain)

    http_artifact = evidence.add(
        artifact_type="http_response",
        source=f"https://{domain}",
        data=http,
        collector="HTTP Collector",
    )

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    tls = analyze_tls(domain)

    tls_artifact = evidence.add(
        artifact_type="tls_certificate",
        source=f"{domain}:443",
        data=tls,
        collector="TLS Collector",
    )

    # ---------------------------------------------------------
    # Certificate Transparency
    # ---------------------------------------------------------

    ct = get_ct_info(domain)

    ct_artifact = evidence.add(
        artifact_type="certificate_transparency",
        source="Cert Spotter",
        data=ct,
        collector="CT Collector",
    )

    # ---------------------------------------------------------
    # CT → DNS → ASN correlation
    # ---------------------------------------------------------

    ct_dns = correlate_ct_with_dns(ct)

    ct_dns_artifact = evidence.add(
        artifact_type="ct_dns_correlation",
        source=(
            "Certificate Transparency + "
            "system DNS resolver + IPWHOIS/RDAP"
        ),
        data=ct_dns,
        collector="CT Correlation Engine",
        classification="derived",
        parent_artifacts=[
            dns_artifact["artifact_id"],
            asn_artifact["artifact_id"],
            ct_artifact["artifact_id"],
        ],
    )

    # ---------------------------------------------------------
    # Infrastructure correlations
    # ---------------------------------------------------------

    ct_infrastructure = (
        build_ct_infrastructure_correlations(
            ct_dns
        )
    )

    ct_infrastructure_findings = (
    build_ct_infrastructure_findings(
        ct_infrastructure
    )
)

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    findings = build_findings(
        domain=domain,
        rdap=rdap,
        dns=dns,
        ip=ip,
        asn=asn,
        http=http,
        tls=tls,
    )

    findings.extend(
        build_ct_findings(ct)
    )

    findings.extend(
        build_correlation_findings(
            domain=domain,
            dns=dns,
            ip=ip,
            asn=asn,
            http=http,
        )
    )

    findings.extend(
    ct_infrastructure_findings
)

    # ---------------------------------------------------------
    # Finding → Evidence artifact linkage
    # ---------------------------------------------------------

    findings = link_findings_to_artifacts(
        findings=findings,
       artifact_ids={
    "rdap": rdap_artifact["artifact_id"],
    "dns": dns_artifact["artifact_id"],
    "ip": ip_artifact["artifact_id"],
    "asn": asn_artifact["artifact_id"],
    "http": http_artifact["artifact_id"],
    "tls": tls_artifact["artifact_id"],
    "ct": ct_artifact["artifact_id"],
    "ct_dns_correlation": (
        ct_dns_artifact["artifact_id"]
    ),
},
    )

    # ---------------------------------------------------------
    # Stable finding IDs
    # ---------------------------------------------------------

    findings = assign_finding_ids(
        findings=findings,
        case_id=case_id,
    )

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------

    collection_completed_at = utc_now()

    report = DomainReport(
        domain=domain,
        case_id=case_id,
        collection_started_at=collection_started_at,
        collection_completed_at=collection_completed_at,
        tool=TOOL_NAME,
        tool_version=TOOL_VERSION,
        collector_versions=COLLECTOR_VERSIONS,
        rdap=rdap,
        dns=dns,
        ip=ip,
        asn=asn,
        http=http,
        tls=tls,
        ct=ct,
        ct_dns=ct_dns,
        ct_infrastructure=ct_infrastructure,
        findings=findings,
        evidence=evidence.artifacts,
        evidence_manifest=evidence.manifest.to_dict(),
    )

    return report.to_dict()