from datetime import datetime, timezone

from ..collectors.ct import normalize_ct_hostname
from ..collectors.dns import resolve_hostname
from ..collectors.asn import get_asn_info
from ..models.evidence import Evidence
from ..models.finding import Finding


def utc_now() -> str:
    """
    Return the current UTC time as an ISO-8601 timestamp.
    """
    return datetime.now(timezone.utc).isoformat()


def correlate_ct_with_dns(ct: dict) -> list[dict]:
    """
    Correlate certificate-associated hostnames with current DNS
    and IP registration data.

    This performs DNS and IP registration lookups only. It does
    not make HTTP, HTTPS, TLS, or other active connections to
    discovered hosts.

    Existing report fields are preserved. Additional observation
    metadata is stored separately for evidentiary traceability.
    """

    if not ct.get("available"):
        return []

    names = ct.get("names", [])

    if not names:
        return []
    grouped = {}

    for ct_name in names:
        if not isinstance(ct_name, str):
            continue

        normalized = normalize_ct_hostname(ct_name)

        if not normalized:
            continue

        grouped.setdefault(normalized, [])

        if ct_name not in grouped[normalized]:
            grouped[normalized].append(ct_name)

    results = []

    for hostname, certificate_names in sorted(grouped.items()):

        dns_observed_at = utc_now()

        dns_result = resolve_hostname(hostname)

        all_ips = (
            dns_result.get("ipv4", [])
            + dns_result.get("ipv6", [])
        )

        asn_result = get_asn_info(all_ips)

        asn_observations = {}

        for ip in all_ips:
            asn_observations[ip] = {
                "observed_at": utc_now(),
                "source": "IPWHOIS/RDAP",
                "method": "IP registration lookup",
            }

        results.append({
            # Existing fields preserved.
            "hostname": hostname,

            "certificate_names": sorted(
                certificate_names
            ),

            "wildcard_certificate_names": sorted(
                name
                for name in certificate_names
                if name.startswith("*.")
            ),

            "exact_certificate_names": sorted(
                name
                for name in certificate_names
                if not name.startswith("*.")
            ),

            "dns": dns_result,
            "asn": asn_result,

            # Existing hostname-level observation metadata.
            "observation": {
                "dns_observed_at": dns_observed_at,
                "asn_observed_at": (
                    min(
                        (
                            observation["observed_at"]
                            for observation
                            in asn_observations.values()
                        ),
                        default=None,
                    )
                ),
                "dns_source": "system DNS resolver",
                "asn_source": "IPWHOIS/RDAP",
                "method": (
                    "passive DNS and IP registration lookup"
                ),
            },

            # New per-IP evidence metadata.
            "asn_observations": asn_observations,
        })

    return results


def build_ct_infrastructure_correlations(
    ct_dns: list[dict],
) -> dict:
    """
    Build infrastructure relationships from the CT → DNS → ASN
    correlation data.

    Relationships are based only on observed current DNS and
    IP registration data.

    Shared infrastructure does not prove common ownership,
    common control, or application-level relationships.
    """

    ip_to_hostnames = {}
    asn_to_hostnames = {}

    for item in ct_dns:
        hostname = item.get("hostname")

        if not hostname:
            continue

        dns = item.get("dns", {})

        ips = (
            dns.get("ipv4", [])
            + dns.get("ipv6", [])
        )

        for ip in ips:
            ip_to_hostnames.setdefault(ip, [])

            if hostname not in ip_to_hostnames[ip]:
                ip_to_hostnames[ip].append(hostname)

            asn_data = item.get("asn", {}).get(ip, {})

            asn_number = asn_data.get("asn")

            if asn_number:
                asn_to_hostnames.setdefault(
                    asn_number,
                    {
                        "hostnames": [],
                        "ips": [],
                        "descriptions": [],
                    },
                )

                entry = asn_to_hostnames[asn_number]

                if hostname not in entry["hostnames"]:
                    entry["hostnames"].append(hostname)

                if ip not in entry["ips"]:
                    entry["ips"].append(ip)

                description = asn_data.get(
                    "asn_description"
                )

                if (
                    description
                    and description not in entry["descriptions"]
                ):
                    entry["descriptions"].append(
                        description
                    )

    shared_ip = {}

    for ip, hostnames in ip_to_hostnames.items():
        if len(hostnames) < 2:
            continue

        shared_ip[ip] = {
            "ip": ip,
            "hostnames": sorted(hostnames),
        }

    shared_asn = {}

    for asn_number, data in asn_to_hostnames.items():
        if len(data["hostnames"]) < 2:
            continue

        shared_asn[str(asn_number)] = {
            "asn": asn_number,
            "hostnames": sorted(data["hostnames"]),
            "ips": sorted(data["ips"]),
            "descriptions": sorted(data["descriptions"]),
        }

    return {
        "shared_ip": shared_ip,
        "shared_asn": shared_asn,
    }

from ..models.evidence import Evidence
from ..models.finding import Finding


def build_ct_infrastructure_findings(
    ct_infrastructure: dict,
) -> list[dict]:
    """
    Convert CT → DNS → ASN infrastructure correlations into
    explicit derived findings.

    These findings represent analytical relationships derived
    from the preserved CT/DNS/ASN correlation artifact.

    Shared infrastructure does not establish common ownership,
    common control, or an application-level relationship.
    """

    findings = []

    # ---------------------------------------------------------
    # Shared IP infrastructure
    # ---------------------------------------------------------

    shared_ip = ct_infrastructure.get(
        "shared_ip",
        {},
    )

    for ip_address, data in sorted(
        shared_ip.items()
    ):
        hostnames = sorted(
            data.get("hostnames", [])
        )

        if len(hostnames) < 2:
            continue

        evidence = Evidence.create(
            value={
                "ip": ip_address,
                "hostnames": hostnames,
            },
            source="CT Infrastructure Correlation",
            record_type="shared_ip",
            confidence="derived",
        )

        findings.append(
            Finding(
                category="correlation",
                name=(
                    f"Shared IP infrastructure: "
                    f"{ip_address}"
                ),
                value={
                    "ip": ip_address,
                    "hostnames": hostnames,
                },
                description=(
                    "Multiple certificate-associated hostnames "
                    "currently resolve to the same observed IP "
                    "address. This indicates shared observed "
                    "network infrastructure, but does not by "
                    "itself establish common ownership, control, "
                    "or an application-level relationship."
                ),
                confidence="low",
                finding_type="correlation",
                evidence=[
                    evidence.to_dict()
                ],
            ).to_dict()
        )

    # ---------------------------------------------------------
    # Shared ASN infrastructure
    # ---------------------------------------------------------

    shared_asn = ct_infrastructure.get(
        "shared_asn",
        {},
    )

    for asn_number, data in sorted(
        shared_asn.items()
    ):
        hostnames = sorted(
            data.get("hostnames", [])
        )

        ips = sorted(
            data.get("ips", [])
        )

        descriptions = sorted(
            data.get("descriptions", [])
        )

        if len(hostnames) < 2:
            continue

        evidence = Evidence.create(
            value={
                "asn": asn_number,
                "hostnames": hostnames,
                "ips": ips,
                "descriptions": descriptions,
            },
            source="CT Infrastructure Correlation",
            record_type="shared_asn",
            confidence="derived",
        )

        findings.append(
            Finding(
                category="correlation",
                name=(
                    f"Shared ASN infrastructure: "
                    f"AS{asn_number}"
                ),
                value={
                    "asn": asn_number,
                    "hostnames": hostnames,
                    "ips": ips,
                    "descriptions": descriptions,
                },
                description=(
                    "Multiple certificate-associated hostnames "
                    "currently resolve to IP addresses registered "
                    "to the same autonomous system. This indicates "
                    "shared observed network infrastructure, but "
                    "does not by itself establish common ownership, "
                    "control, or an application-level relationship."
                ),
                confidence="low",
                finding_type="correlation",
                evidence=[
                    evidence.to_dict()
                ],
            ).to_dict()
        )

    return findings

