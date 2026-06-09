# BSOT Documentation

**Blue Security Operations Toolkit** - A comprehensive CLI toolkit for security analysts.

---

## What is BSOT?

BSOT (pronounced "bee-sot") is a unified command-line toolkit that brings together essential security operations capabilities. Built for analysts, by analysts.

```bash
# Analyze a phishing email
bsot phishing analyze suspicious.eml

# Enrich an IOC
bsot intel enrich 8.8.8.8

# Hash a file
bsot file hash malware.exe --all
```

---

## Key Features

<div class="grid cards" markdown>

-   :material-email-search: **Phishing Analysis**

    ---

    Parse email headers, extract IOCs, check reputation, and use AI for analysis.

    [:octicons-arrow-right-24: Learn more](modules/phishing.md)

-   :material-magnify: **Threat Intelligence**

    ---

    Enrich IOCs via VirusTotal, AbuseIPDB, GreyNoise, OTX, and more.

    [:octicons-arrow-right-24: Learn more](modules/intel.md)

-   :material-file-search: **File Analysis**

    ---

    Hash files, identify types, extract strings, and analyze entropy.

    [:octicons-arrow-right-24: Learn more](modules/file.md)

-   :material-web: **Network Security**

    ---

    Check SSL certificates, audit headers, analyze DNS security.

    [:octicons-arrow-right-24: Learn more](modules/network.md)

-   :material-text-search: **Log Analysis**

    ---

    Parse and analyze logs for attack patterns like brute force.

    [:octicons-arrow-right-24: Learn more](modules/logs.md)

-   :material-bug: **Malware Analysis**

    ---

    PE analysis, YARA scanning, deobfuscation, sandbox submission.

    [:octicons-arrow-right-24: Learn more](modules/malware.md)

</div>

---

## Quick Start

### Installation

```bash
pip install bsot
```

Or download the standalone binary from the [releases page](https://github.com/yourusername/bsot/releases).

### Basic Usage

```bash
# Get help
bsot --help

# Analyze an email
bsot phishing analyze email.eml

# Enrich an IOC
bsot intel enrich suspicious-domain.com

# Hash a file
bsot file hash sample.exe
```

[:octicons-arrow-right-24: Full Getting Started Guide](getting-started/quick-start.md)

---

## Modules

| Module | Description |
|--------|-------------|
| [phishing](modules/phishing.md) | Email phishing analysis |
| [intel](modules/intel.md) | Threat intelligence & IOC enrichment |
| [file](modules/file.md) | File analysis & hashing |
| [network](modules/network.md) | Network security analysis |
| [logs](modules/logs.md) | Log parsing & analysis |
| [data](modules/data.md) | Data encoding/decoding |
| [auth](modules/auth.md) | Authentication analysis |
| [system](modules/system.md) | System analysis |
| [ir](modules/ir.md) | Incident response |
| [malware](modules/malware.md) | Malware analysis |
| [report](modules/report.md) | Reporting & case management |
| [osint](modules/osint.md) | Open source intelligence |

---

## Use Cases

- [Phishing Investigation](use-cases/phishing-investigation.md) - Analyze suspicious emails end-to-end
- [Malware Triage](use-cases/malware-triage.md) - Quick static analysis workflow
- [Incident Response](use-cases/incident-response.md) - Full IR from detection to documentation
- [Threat Hunting](use-cases/threat-hunting.md) - Proactive threat hunting
- [Log Analysis](use-cases/log-analysis.md) - Finding attack patterns in logs

---

## Getting Help

- [Examples](examples/index.md) - Quick command examples
- [CLI Reference](reference/cli.md) - Complete command reference
- [GitHub Issues](https://github.com/yourusername/bsot/issues) - Report bugs, request features
- [Marketing Site](/) - Back to homepage
