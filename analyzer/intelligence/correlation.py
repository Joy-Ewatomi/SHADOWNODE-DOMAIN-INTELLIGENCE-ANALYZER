from ..models.evidence import Evidence
from ..models.finding import Finding


def build_correlation_findings(
    domain: str,
    dns: dict,
    ip: dict,
    asn: dict,
    http: dict,
) -> list[dict]:

    findings = []

    nameservers = [
        ns.lower()
        for ns in dns.get("ns", {}).get("records", [])
    ]

    server = (http.get("server") or "").lower()

    cloudflare_ns = [
        ns
        for ns in nameservers
        if "cloudflare.com" in ns
    ]

    cloudflare_http = server == "cloudflare"

    if cloudflare_ns and cloudflare_http:
        evidence = [
            Evidence.create(
                value=cloudflare_ns,
                source="DNS",
                record_type="NS",
                confidence="observed",
            ).to_dict(),
            Evidence.create(
                value=server,
                source="HTTP",
                record_type="Server",
                confidence="observed",
            ).to_dict(),
        ]

        findings.append(
            Finding(
    category="correlation",
    name="Cloudflare infrastructure relationship",
    value=True,
    description=(
        "DNS delegation and HTTP response metadata "
        "both indicate Cloudflare involvement in "
        "the observed domain infrastructure."
    ),
    evidence=evidence,
    confidence="high",
    finding_type="correlation",
).to_dict()
        )

    cf_mitigated = http.get("headers", {}).get("cf-mitigated")

    if cloudflare_http and cf_mitigated:
        evidence = [
            Evidence.create(
                value=server,
                source="HTTP",
                record_type="Server",
                confidence="observed",
            ).to_dict(),
            Evidence.create(
                value=cf_mitigated,
                source="HTTP",
                record_type="cf-mitigated",
                confidence="observed",
            ).to_dict(),
        ]

        findings.append(
          Finding(
    category="correlation",
    name="Cloudflare edge protection indicator",
    value=True,
    description=(
        "The HTTP response identifies Cloudflare "
        "and also exposes a Cloudflare mitigation "
        "indicator."
    ),
    evidence=evidence,
    confidence="high",
    finding_type="correlation",
).to_dict()
        )

    # IP / ASN correlation
    observed_asns = {}

    for ip_address, asn_data in asn.items():
        asn_number = asn_data.get("asn")

        if not asn_number:
            continue

        observed_asns.setdefault(asn_number, []).append(
            ip_address
        )

    for asn_number, ip_addresses in observed_asns.items():

        asn_records = [
            asn[ip_address]
            for ip_address in ip_addresses
            if ip_address in asn
        ]

        descriptions = {
            record.get("asn_description")
            for record in asn_records
            if record.get("asn_description")
        }

        networks = [
            record.get("network")
            for record in asn_records
            if record.get("network")
        ]

        evidence = []

        for ip_address in ip_addresses:
            record = asn.get(ip_address)

            if not record:
                continue

            evidence.append(
                Evidence.create(
                    value=record,
                    source="IPWHOIS/RDAP",
                    record_type="ASN",
                    confidence="observed",
                ).to_dict()
            )

        findings.append(
            Finding(
                category="correlation",
                name=f"Shared ASN infrastructure: AS{asn_number}",
                value={
                    "asn": asn_number,
                    "ips": ip_addresses,
                    "descriptions": list(descriptions),
                    "networks": networks,
                },
                description=(
                    f"Multiple observed IP addresses associated "
                    f"with the domain resolve to the same "
                    f"autonomous system, AS{asn_number}."
                ),
                confidence="high",
                finding_type="correlation",
                evidence=evidence,
            ).to_dict()
        )
        
    return findings
