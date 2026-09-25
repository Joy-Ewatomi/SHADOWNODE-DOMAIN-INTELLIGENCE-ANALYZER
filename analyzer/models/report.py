from dataclasses import dataclass, field


@dataclass
class DomainReport:
    domain: str

    # Investigation metadata.
    case_id: str | None = None
    run_id: str | None = None
    collection_started_at: str | None = None
    collection_completed_at: str | None = None
    tool: str = "ShadowNode Domain Intelligence Analyzer"
    tool_version: str = "0.1.0"
    collector_versions: dict[str, str] = field(
        default_factory=dict
    )

    rdap: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    ip: dict = field(default_factory=dict)
    asn: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    ct: dict = field(default_factory=dict)
    ct_dns: list[dict] = field(default_factory=list)
    ct_infrastructure: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)

    # Evidence-preservation fields.
    evidence: list[dict] = field(default_factory=list)
    evidence_manifest: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,

            # Investigation metadata.
            "case_id": self.case_id,
            "run_id": self.run_id,
            "collection_started_at": (
                self.collection_started_at
            ),
            "collection_completed_at": (
                self.collection_completed_at
            ),
            "tool": self.tool,
            "tool_version": self.tool_version,
            "collector_versions": (
                self.collector_versions
            ),

            "rdap": self.rdap,
            "dns": self.dns,
            "ip": self.ip,
            "asn": self.asn,
            "http": self.http,
            "tls": self.tls,
            "ct": self.ct,
            "ct_dns": self.ct_dns,
            "ct_infrastructure": self.ct_infrastructure,
            "findings": self.findings,

            # Evidence-preservation fields.
            "evidence": self.evidence,
            "evidence_manifest": self.evidence_manifest,
        }
