# Modules

BSOT is organized into focused modules, each addressing a specific security domain.

---

## Module Overview

<div class="grid cards" markdown>

-   :material-email-search: **[Phishing](phishing.md)**

    ---

    Email analysis: parse headers, extract IOCs, check reputation, AI analysis.

-   :material-magnify: **[Intel](intel.md)**

    ---

    Threat intelligence: enrich IOCs via VirusTotal, AbuseIPDB, GreyNoise, and more.

-   :material-file-search: **[File](file.md)**

    ---

    File analysis: hashing, identification, strings, entropy, metadata.

-   :material-web: **[Network](network.md)**

    ---

    Network security: SSL/TLS, HTTP headers, DNS security, port scanning.

-   :material-text-search: **[Logs](logs.md)**

    ---

    Log analysis: parsing, attack detection, statistics.

-   :material-code-tags: **[Data](data.md)**

    ---

    Data operations: encoding/decoding, timestamps, hashing, regex.

-   :material-key: **[Auth](auth.md)**

    ---

    Authentication: password analysis, JWT decoding.

-   :material-monitor: **[System](system.md)**

    ---

    System analysis: processes, network connections.

-   :material-ambulance: **[IR](ir.md)**

    ---

    Incident response: artifact collection, containment, Cloudflare integration.

-   :material-bug: **[Malware](malware.md)**

    ---

    Malware analysis: PE analysis, YARA, deobfuscation, sandbox submission.

-   :material-clipboard-text: **[Report](report.md)**

    ---

    Reporting: case management, report generation, IOC export.

-   :material-earth: **[OSINT](osint.md)**

    ---

    Open source intelligence: domain recon, email lookup, username search.

</div>

---

## Quick Reference

| Module | Primary Use Case | Key Commands |
|--------|-----------------|--------------|
| `phishing` | Email investigation | `analyze`, `extract-iocs`, `headers` |
| `intel` | IOC enrichment | `enrich`, `bulk`, `whois` |
| `file` | File triage | `hash`, `identify`, `strings` |
| `network` | Network assessment | `ssl-check`, `headers`, `dns` |
| `logs` | Log analysis | `analyze`, `parse`, `stats` |
| `data` | Data manipulation | `decode`, `encode`, `timestamp` |
| `auth` | Credential analysis | `password-analyze`, `jwt-decode` |
| `system` | System investigation | `processes`, `connections` |
| `ir` | Incident handling | `collect`, `contain`, `cf` |
| `malware` | Malware analysis | `pe`, `yara`, `deobfuscate` |
| `report` | Documentation | `case`, `generate`, `ioc` |
| `osint` | OSINT gathering | `domain`, `email`, `username` |

---

## Module Categories

### Investigation

- **Phishing**: Email-focused investigation
- **Intel**: IOC enrichment and context
- **OSINT**: Open source intelligence gathering

### Analysis

- **File**: Static file analysis
- **Malware**: Deep malware analysis
- **Logs**: Log forensics

### Assessment

- **Network**: Network security posture
- **Auth**: Authentication security
- **System**: Endpoint assessment

### Response

- **IR**: Incident response actions
- **Report**: Documentation and case management

### Utilities

- **Data**: Data transformation and encoding

---

## Common Patterns

### JSON Output

All modules support JSON output for scripting:

```bash
bsot <module> <command> --json
```

### File Input

Many commands accept file input:

```bash
bsot <module> <command> -f input.txt
```

### Output to File

Save results to a file:

```bash
bsot <module> <command> -o output.json
```

---

## See Also

- [Examples](../examples/index.md) - Quick command reference
- [CLI Reference](../reference/cli.md) - Complete command documentation
- [Use Cases](../use-cases/index.md) - Real-world workflows
