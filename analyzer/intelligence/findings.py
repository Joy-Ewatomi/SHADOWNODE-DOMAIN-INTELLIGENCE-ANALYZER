from ..models.evidence import Evidence
from ..models.finding import Finding


def build_findings(
    domain: str,
    rdap: dict,
    dns: dict,
    ip: dict,
    asn: dict,
    http: dict,
    tls: dict,
) -> list[dict]:

    findings = []

    # ---------------------------------------------------------
    # DNS / Infrastructure
    # ---------------------------------------------------------

    nameservers = dns.get("ns", {}).get("records", [])

    cloudflare_nameservers = [
        ns for ns in nameservers
        if "cloudflare.com" in ns.lower()
    ]

    if cloudflare_nameservers:
        evidence = Evidence.create(
            value=cloudflare_nameservers,
            source="DNS",
            record_type="NS",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="infrastructure",
                name="Cloudflare nameservers",
                value=True,
                description=(
                    "The domain delegates DNS to Cloudflare "
                    "nameservers."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # IP / ASN infrastructure
    # ---------------------------------------------------------

    for ip_address, asn_data in asn.items():

        asn_number = asn_data.get("asn")

        if not asn_number:
            continue

        evidence = Evidence.create(
            value={
                "ip": ip_address,
                "asn": asn_number,
                "asn_cidr": asn_data.get("asn_cidr"),
                "asn_description": asn_data.get("asn_description"),
                "asn_registry": asn_data.get("asn_registry"),
                "network": asn_data.get("network"),
            },
            source="IPWHOIS/RDAP",
            record_type="ASN",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="infrastructure",
                name=f"ASN for {ip_address}",
                value=asn_number,
                description=(
                    f"The observed IP address {ip_address} "
                    f"is associated with autonomous system "
                    f"AS{asn_number} according to IP registration "
                    f"and RDAP data."
                ),
                confidence="observed",
                finding_type="observation",
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # HTTP infrastructure
    # ---------------------------------------------------------

    server = http.get("server")

    if server:
        evidence = Evidence.create(
            value=server,
            source="HTTP",
            record_type="Server",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="infrastructure",
                name="HTTP server",
                value=server,
                description=(
                    "The HTTP response identifies the server "
                    "software or infrastructure provider."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # Cloudflare challenge
    # ---------------------------------------------------------

    headers = http.get("headers", {})

    cf_mitigated = headers.get("cf-mitigated")

    if cf_mitigated:
        evidence = Evidence.create(
            value=cf_mitigated,
            source="HTTP",
            record_type="cf-mitigated",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="access",
                name="Cloudflare mitigation detected",
                value=cf_mitigated,
                description=(
                    "The HTTP response indicates that a "
                    "Cloudflare mitigation or challenge was "
                    "present during collection."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # HTTP status
    # ---------------------------------------------------------

    status_code = http.get("status_code")

    if status_code is not None:
        evidence = Evidence.create(
            value=status_code,
            source="HTTP",
            record_type="status_code",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="web",
                name="HTTP response status",
                value=status_code,
                description=(
                    f"The HTTPS endpoint returned HTTP "
                    f"status {status_code}."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    tls_version = tls.get("tls_version")

    if tls_version:
        evidence = Evidence.create(
            value=tls_version,
            source="TLS",
            record_type="protocol",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="tls",
                name="TLS protocol",
                value=tls_version,
                description=(
                    "The HTTPS endpoint negotiated this TLS "
                    "protocol version."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # Certificate
    # ---------------------------------------------------------

    certificate = tls.get("certificate", {})

    # Certificate SANs
    san_entries = certificate.get("san", [])

    if san_entries:
        evidence = Evidence.create(
            value=san_entries,
            source="TLS",
            record_type="subjectAltName",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="certificate",
                name="Certificate SANs",
                value=san_entries,
                description=(
                    "The TLS certificate presented for the "
                    "domain contains these Subject Alternative "
                    "Names. Their presence on the certificate "
                    "does not by itself establish that the "
                    "hostnames are currently active."
                ),
                confidence="observed",
                finding_type="observation",
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # Certificate issuer
    # ---------------------------------------------------------

    issuer = certificate.get("issuer", {})

    if issuer:
        evidence = Evidence.create(
            value=issuer,
            source="TLS",
            record_type="certificate_issuer",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="tls",
                name="Certificate issuer",
                value=issuer,
                description=(
                    "The TLS certificate was issued by the "
                    "identified certificate authority."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # Certificate expiration
    # ---------------------------------------------------------

    days_remaining = certificate.get("days_remaining")

    if days_remaining is not None:
        evidence = Evidence.create(
            value=days_remaining,
            source="TLS",
            record_type="certificate_expiration",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="tls",
                name="Certificate validity",
                value={
                    "days_remaining": days_remaining,
                    "expired": certificate.get("expired"),
                },
                description=(
                    "The TLS certificate validity period was "
                    "observed during collection."
                ),
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # Security headers
    # ---------------------------------------------------------

    security_headers = http.get("security_headers", {})

    for header, value in security_headers.items():

        if value:
            evidence = Evidence.create(
                value=value,
                source="HTTP",
                record_type=header,
                confidence="observed",
            )

            findings.append(
                Finding(
                    category="security",
                    name=f"Security header: {header}",
                    value=value,
                    description=(
                        "The HTTP response included this "
                        "security-related response header."
                    ),
                    evidence=[evidence.to_dict()],
                ).to_dict()
            )

    return findings


def build_ct_findings(ct: dict) -> list[dict]:
    findings = []

    if not ct.get("available"):
        return findings

    certificate_count = ct.get("certificate_count", 0)
    names = ct.get("names", [])

    if certificate_count:
        evidence = Evidence.create(
            value=certificate_count,
            source="Cert Spotter",
            record_type="certificate_count",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="certificate_transparency",
                name="CT certificates observed",
                value=certificate_count,
                description=(
                    "Certificate Transparency data contains "
                    "this number of certificate issuance records "
                    "for the queried domain and its subdomains."
                ),
                confidence="observed",
                finding_type="observation",
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    if names:
        evidence = Evidence.create(
            value=names,
            source="Cert Spotter",
            record_type="certificate_dns_names",
            confidence="observed",
        )

        findings.append(
            Finding(
                category="certificate_transparency",
                name="Certificate-associated hostnames",
                value=names,
                description=(
                    "These hostnames appeared in publicly observed "
                    "TLS certificates associated with the domain. "
                    "Certificate presence does not establish that "
                    "a hostname is currently active."
                ),
                confidence="observed",
                finding_type="observation",
                evidence=[evidence.to_dict()],
            ).to_dict()
        )

    return findings