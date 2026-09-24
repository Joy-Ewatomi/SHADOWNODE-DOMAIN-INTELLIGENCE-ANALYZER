SHADOWNODE-WHOIS-ANALYZER

**Domain Analyzer** is a passive OSINT domain intelligence and evidence-preservation tool written in Python.

It collects publicly observable information about a domain, normalizes the results, correlates related infrastructure, preserves collection evidence, and produces findings that can be independently verified.

The project is designed around an important principle:

> **Observed evidence should remain distinguishable from analytical conclusions.**

Instead of treating a finding as an isolated claim, Domain Analyzer maintains relationships between findings and the evidence artifacts that support them.

---

## Features

### Passive Domain Intelligence

Domain Analyzer currently supports:

* RDAP domain registration information
* RDAP registry and registrar metadata
* Domain status information
* Nameserver discovery
* Registration and lifecycle events
* DNS record collection
* IPv4 resolution
* IPv6 resolution
* Reverse DNS observations
* ASN and network ownership observations
* HTTP response analysis
* HTTP security-header analysis
* TLS protocol and certificate analysis
* Certificate Transparency collection
* CT hostname normalization
* CT-to-DNS correlation
* Shared IP infrastructure correlation
* Shared ASN infrastructure correlation

### Evidence Preservation

Every collection run can produce structured evidence artifacts containing:

* Stable artifact IDs
* Artifact type
* Collection source
* Collection timestamp
* Collector name
* Collector version
* Evidence classification
* Parent artifact references
* SHA-256 integrity hashes

A collection-level evidence manifest records the artifacts and provides an additional integrity layer.

### Finding Provenance

Analytical findings are assigned stable finding IDs and maintain references to the evidence artifacts supporting them.

This makes it possible to trace:

```text
Finding
   |
   +-- Evidence Artifact
   |
   +-- Evidence Artifact
   |
   +-- Evidence Artifact
```

Derived correlations also retain references to the artifacts from which they were produced.

---

# Architecture

The project follows a collection → normalization → correlation → evidence model.

```text
                         Domain
                           |
                           v
                    +--------------+
                    |  Collectors  |
                    +--------------+
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
         DNS             RDAP             HTTP
          |                |                |
          +----------------+----------------+
                           |
                           v
                    +--------------+
                    | Normalization|
                    +--------------+
                           |
                           v
                    +--------------+
                    | Correlation  |
                    +--------------+
                           |
                           v
                    +--------------+
                    |   Evidence   |
                    +--------------+
                           |
                           v
                    +--------------+
                    |   Findings   |
                    +--------------+
                           |
                           v
                    +--------------+
                    |    Report    |
                    +--------------+
                           |
                           v
                    +--------------+
                    | Verification |
                    +--------------+
```

The architecture separates four major concepts:

### Collection

Collectors retrieve publicly observable information from external services and protocols.

### Normalization

Collector output is converted into consistent structures suitable for comparison and correlation.

### Correlation

The intelligence layer identifies relationships between observations.

### Evidence

Raw observations and derived relationships are preserved as structured artifacts with integrity metadata.

---

# Project Structure

```text
domain-analyzer/
├── analyzer/
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── dns.py
│   │   ├── rdap.py
│   │   ├── ip.py
│   │   ├── asn.py
│   │   ├── http.py
│   │   ├── tls.py
│   │   └── ct.py
│   │
│   ├── evidence/
│   │   ├── __init__.py
│   │   ├── hashing.py
│   │   ├── artifacts.py
│   │   ├── manifest.py
│   │   ├── collector.py
│   │   └── verify.py
│   │
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── findings.py
│   │   ├── correlation.py
│   │   └── ct_correlation.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── evidence.py
│   │   ├── finding.py
│   │   └── report.py
│   │
│   ├── core.py
│   └── __init__.py
│
├── tests/
│   ├── __init__.py
│   ├── test_core_integration.py
│   ├── test_evidence.py
│   ├── test_ct_correlation.py
│   ├── test_ct_dns_correlation.py
│   ├── test_dns_collector.py
│   ├── test_ip_collector.py
│   ├── test_http_collector.py
│   ├── test_tls_collector.py
│   ├── test_ct_collector.py
│   └── test_rdap_collector.py
│
├── main.py
├── verify_report.py
├── requirements.txt
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

---

# Requirements

Domain Analyzer currently targets:

* Python 3.12+
* Internet connectivity for external passive data sources
* A working DNS resolver
* OpenSSL/TLS support provided by Python
* Linux, macOS, or another supported Python environment

The tool does **not** require a database for the core command-line workflow.

---

# Installation

## 1. Clone the repository

After the project is published:

```bash
git clone https://github.com/Joy-Ewatomi/domain-analyzer.git
cd domain-analyzer
```

Replace `YOUR-USERNAME` with the GitHub account containing the repository.

If you are working from an existing local checkout, simply enter the project directory:

```bash
cd domain-analyzer
```

---

## 2. Create a virtual environment

Using a virtual environment keeps the project's Python dependencies isolated from the operating system.

```bash
python3 -m venv .venv
```

---

## 3. Activate the virtual environment

### Linux / macOS

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

After activation, your shell should show something similar to:

```text
(.venv)
```

---

## 4. Upgrade pip

```bash
python -m pip install --upgrade pip
```

---

## 5. Install dependencies

Install the project's dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## 6. Verify the installation

Run the test suite:

```bash
python -m pytest -q
```

A successful installation should result in all tests passing.

---

# Basic Usage

Analyze a domain with:

```bash
python main.py example.com
```

The command writes the complete JSON report to standard output.

For practical use, save the report to a file:

```bash
python main.py example.com > report.json
```

The resulting file contains the collector results, evidence artifacts, findings, and evidence manifest.

---

# Report Metadata

Reports contain investigation metadata including:

```json
{
  "domain": "example.com",
  "case_id": "domain-example-com",
  "collection_started_at": "...",
  "collection_completed_at": "...",
  "tool": "Domain Analyzer",
  "tool_version": "1.0",
  "collector_versions": {}
}
```

The metadata helps establish:

* Which domain was analyzed
* Which case the collection belongs to
* When collection started
* When collection finished
* Which tool generated the report
* Which version of the tool generated it
* Which versions of individual collectors were used

Timestamps are recorded using UTC.

---

# Evidence Model

Domain Analyzer distinguishes between **observed** and **derived** information.

## Observed Evidence

Observed evidence represents information directly returned or observed by a collector.

Examples include:

* DNS records returned by a resolver
* RDAP registration data
* HTTP response metadata
* TLS certificate information
* Certificate Transparency records
* IP resolution results

An observed artifact records the source and collection time.

---

## Derived Evidence

Derived evidence represents an analytical relationship created from previously collected observations.

For example:

```text
Certificate Transparency
        |
        v
Hostname
        |
        v
DNS Resolution
        |
        v
Observed IP
        |
        v
Infrastructure Correlation
```

A derived artifact records its parent artifacts so that the analytical relationship can be traced back to the underlying observations.

---

# Evidence Integrity

Evidence artifacts are hashed using SHA-256.

A simplified artifact structure looks like:

```json
{
  "artifact_id": "domain-example-com-0001",
  "artifact_type": "dns",
  "source": "DNS resolver",
  "collected_at": "...",
  "sha256": "...",
  "collector": "DNS Collector",
  "collector_version": "1.0",
  "classification": "observed"
}
```

The evidence manifest contains the collection-level integrity information.

This allows the verification utility to detect changes to the stored evidence.

---

# Report Verification

After generating a report:

```bash
python main.py example.com > report.json
```

verify it with:

```bash
python verify_report.py report.json
```

A valid report should produce output similar to:

```text
Overall valid: True
Artifacts: 8
Verified: 8
Failed: 0
Artifact provenance: True
Artifact provenance errors: 0
Finding identity: True
Finding identity errors: 0
Finding provenance: True
Finding provenance errors: 0
Manifest valid: True
```

The number of artifacts can change as the collection pipeline evolves.

Verification checks:

1. Artifact hashes
2. Artifact provenance
3. Finding identity
4. Finding provenance
5. Evidence manifest integrity

---

# Findings

Findings are separate from raw collector results.

A finding may contain:

```text
finding_id
category
name
value
description
confidence
finding_type
evidence_artifacts
```

This separation is intentional.

For example, a collector may observe:

```text
hostname → IP address
```

while the intelligence layer may derive:

```text
Multiple certificate-associated hostnames resolve
to the same observed IP address.
```

The derived statement remains linked to the original observations.

---

# Infrastructure Correlation

The project can identify infrastructure relationships involving:

* Shared IP addresses
* Shared ASNs
* Certificate-associated hostnames
* DNS observations

These relationships should be interpreted carefully.

For example, if multiple hostnames resolve to the same IP address, the result indicates **shared observed network infrastructure**.

It does not, by itself, establish:

* common ownership
* common administrative control
* common application ownership
* intentional association
* organizational affiliation

Similarly, an ASN identifies a network registration relationship and should not automatically be interpreted as proof that all domains or systems associated with that ASN belong to the same organization.

---

# Certificate Transparency

Certificate Transparency data provides certificate-associated hostname observations.

Domain Analyzer normalizes CT hostnames by:

* converting names to lowercase
* removing trailing dots
* removing wildcard prefixes such as `*.`

CT observations are historical/certificate-associated data.

A hostname appearing in Certificate Transparency does **not** automatically prove that the hostname is currently live.

Current DNS resolution and other observations are therefore kept separate from CT discovery.

---

# Collector Error Handling

Collectors preserve meaningful failure states instead of treating every failure as an empty result.

Examples include:

```text
timeout
connection_error
dns_error
http_error
tls_error
certificate_error
resolution_error
no_answer
not_found
invalid_json
```

This distinction is important because:

```text
No result
```

does not necessarily mean:

```text
The requested resource does not exist.
```

A timeout, resolver failure, HTTP error, and genuine empty response represent different observations.

---

# Testing

The project contains automated tests for:

* Evidence hashing
* Evidence artifact creation
* Evidence manifests
* Manifest integrity
* Tamper detection
* Artifact provenance
* Finding identity
* Finding provenance
* DNS collection
* IP collection
* HTTP collection
* TLS collection
* Certificate Transparency collection
* RDAP collection
* CT correlation
* CT/DNS correlation
* Core pipeline integration

Run the complete test suite:

```bash
python -m pytest -q
```

Run an individual test module:

```bash
python -m pytest -q tests/test_evidence.py
```

Run the integration tests:

```bash
python -m pytest -q tests/test_core_integration.py
```

---

# Development Workflow

A typical development cycle is:

```bash
source .venv/bin/activate

python -m pytest -q

python main.py example.com > report.json

python verify_report.py report.json
```

Before committing changes:

```bash
python -m pytest -q
```

Generated investigation reports should not be committed to the repository.

---

# Security and Privacy

Domain Analyzer is designed for passive intelligence collection, but collected information may still be sensitive.

Reports can contain:

* IP addresses
* DNS infrastructure
* network registration information
* certificate metadata
* hostnames
* HTTP metadata
* timestamps
* analytical relationships

Treat generated reports as investigation data.

Do not publish real investigation reports containing sensitive information without authorization.

The included `.gitignore` excludes generated reports such as:

```text
report.json
reports/
*.report.json
```

---

# Responsible Use

Domain Analyzer is intended for legitimate security research, infrastructure analysis, defensive security, digital investigations, and other authorized purposes.

Only investigate domains and infrastructure where you have an appropriate legal or operational basis to do so.

Users are responsible for complying with:

* applicable laws
* organizational policies
* service terms
* privacy requirements
* authorization boundaries
* applicable data-protection requirements

The tool is designed to collect publicly observable information. This does not remove the responsibility to use that information appropriately.

---

# Limitations

Domain Analyzer is an observation and correlation tool.

It does not guarantee:

* ownership attribution
* identity attribution
* infrastructure ownership
* historical completeness
* current availability of every discovered hostname
* definitive relationships between correlated systems
* legal admissibility of generated evidence

Network infrastructure changes over time, so DNS, IP, ASN, HTTP, TLS, and other observations represent the state observed during a particular collection.

External services can also change their responses, availability, rate limits, and data.

---

# Evidence and Legal Context

The evidence-preservation functionality is designed to improve traceability, reproducibility, and integrity checking.

It should not be interpreted as a guarantee that generated reports are automatically admissible as evidence in any particular legal proceeding.

Where evidentiary requirements matter, investigators should follow the applicable organizational, forensic, legal, and chain-of-custody procedures for their jurisdiction and investigation.

---

# Roadmap

Planned project improvements include:

* Expanded collector coverage
* More comprehensive test coverage
* Cleaner package distribution
* Additional evidence formats
* Improved report export
* API integration
* Investigation UI
* More correlation capabilities
* Configuration support
* Improved documentation
* Release automation

---

# Version

Current development version:

```text
0.1.0
```

This release focuses on the core passive collection, correlation, evidence-preservation, provenance, and verification pipeline.

---