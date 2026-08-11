# CLI Reference

Complete command reference for BSOT.

---

## Global Options

```bash
bsot [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help and exit |

---

## Modules

| Module | Description |
|--------|-------------|
| [`phishing`](#phishing) | Email phishing analysis |
| [`intel`](#intel) | Threat intelligence & IOC enrichment |
| [`file`](#file) | File analysis & hashing |
| [`network`](#network) | Network security analysis |
| [`logs`](#logs) | Log parsing & analysis |
| [`data`](#data) | Data encoding/decoding |
| [`auth`](#auth) | Authentication analysis |
| [`system`](#system) | System analysis |
| [`ir`](#ir) | Incident response |
| [`malware`](#malware) | Malware analysis |
| [`osint`](#osint) | Open source intelligence |
| [`report`](#report) | Reporting & case management |
| [`config`](#config) | Configuration management |
| [`cache`](#cache) | Cache management |

---

## phishing

Email phishing analysis.

### analyze

Analyze an email file.

```bash
bsot phishing analyze [OPTIONS] EMAIL_PATH
```

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |
| `--no-color` | Disable color output |

### extract-iocs

Extract IOCs from email.

```bash
bsot phishing extract-iocs [OPTIONS] EMAIL_PATH
```

| Option | Description |
|--------|-------------|
| `--format` | Output format: `text`, `json`, `csv` |

### headers

Analyze email headers (SPF/DKIM/DMARC).

```bash
bsot phishing headers [OPTIONS] EMAIL_PATH
```

### ai-analyze

Analyze email with AI.

```bash
bsot phishing ai-analyze [OPTIONS] EMAIL_PATH
```

| Option | Description |
|--------|-------------|
| `--provider` | AI provider: `openai`, `anthropic` |

### reputation

Check URL/domain reputation.

```bash
bsot phishing reputation [OPTIONS] URL
```

---

## intel

Threat intelligence and IOC enrichment.

### enrich

Enrich a single IOC.

```bash
bsot intel enrich [OPTIONS] IOC
```

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

### bulk

Bulk enrich IOCs from file.

```bash
bsot intel bulk [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-f, --file` | Input file with IOCs |
| `--progress` | Show progress bar |
| `--json` | Output as JSON |
| `-o, --output` | Output file |

### whois

WHOIS lookup.

```bash
bsot intel whois [OPTIONS] DOMAIN
```

### geoip

GeoIP lookup.

```bash
bsot intel geoip [OPTIONS] IP
```

### defang

Defang IOC for safe sharing.

```bash
bsot intel defang IOC
```

### refang

Refang a defanged IOC.

```bash
bsot intel refang IOC
```

---

## file

File analysis and hashing.

### hash

Calculate file hashes.

```bash
bsot file hash [OPTIONS] FILE
```

| Option | Description |
|--------|-------------|
| `--all` | Calculate all hash types |
| `--json` | Output as JSON |
| `-r, --recursive` | Process directories recursively |

### identify

Identify file type.

```bash
bsot file identify [OPTIONS] FILE
```

### strings

Extract strings from file.

```bash
bsot file strings [OPTIONS] FILE
```

| Option | Description |
|--------|-------------|
| `--min-length` | Minimum string length (default: 4) |
| `--category` | Filter by category |

### entropy

Calculate file entropy.

```bash
bsot file entropy [OPTIONS] FILE
```

### metadata

Extract file metadata.

```bash
bsot file metadata [OPTIONS] FILE
```

### cred-scan

Scan for credentials in files.

```bash
bsot file cred-scan [OPTIONS] PATH
```

| Option | Description |
|--------|-------------|
| `-r, --recursive` | Scan directories recursively |
| `--baseline PATH` | Suppress findings recorded by `cred-baseline` |

### cred-baseline

Record current cred-scan findings as accepted, for `cred-scan --baseline`.

```bash
bsot file cred-baseline [OPTIONS] PATH
```

| Option | Description |
|--------|-------------|
| `-o, --output PATH` | Baseline file to write (required) |

---

## network

Network security analysis.

### ssl-check

Check SSL/TLS certificate.

```bash
bsot network ssl-check [OPTIONS] HOST
```

| Option | Description |
|--------|-------------|
| `--port` | Port number (default: 443) |
| `--json` | Output as JSON |

### headers

Audit HTTP security headers.

```bash
bsot network headers [OPTIONS] URL
```

### dns

Analyze DNS security (SPF/DKIM/DMARC).

```bash
bsot network dns [OPTIONS] DOMAIN
```

| Option | Description |
|--------|-------------|
| `--all` | Check all DNS security |
| `--spf` | Check SPF only |
| `--dkim` | Check DKIM only |
| `--dmarc` | Check DMARC only |

### ports

Scan common ports.

```bash
bsot network ports [OPTIONS] HOST
```

---

## logs

Log parsing and analysis.

### parse

Parse log files.

```bash
bsot logs parse [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-f, --file` | Input log file |
| `--format` | Log format: `auto`, `syslog`, `json`, `clf`, `cef` |
| `--limit` | Limit output lines |

### analyze

Analyze logs for attack patterns.

```bash
bsot logs analyze [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-f, --file` | Input log file |
| `--checks` | Specific checks to run |
| `--json` | Output as JSON |
| `-o, --output` | Output file |

### stats

Generate log statistics.

```bash
bsot logs stats [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-f, --file` | Input log file |
| `--top-ips` | Show top N IPs |
| `--by-hour` | Group by hour |

---

## data

Data encoding and decoding.

### decode

Decode data.

```bash
bsot data decode [OPTIONS] [DATA]
```

| Option | Description |
|--------|-------------|
| `-e, --encoding` | Encoding type |

Encoding types: `base64`, `url`, `hex`, `html`, `unicode-escape`, `rot13`, `punycode`

### encode

Encode data.

```bash
bsot data encode [OPTIONS] [DATA]
```

### timestamp

Convert timestamps.

```bash
bsot data timestamp [OPTIONS] TIMESTAMP
```

### hash

Hash data.

```bash
bsot data hash [OPTIONS] DATA
```

### regex

Test regex patterns.

```bash
bsot data regex [OPTIONS] PATTERN DATA
```

### format

Format data (JSON, XML, HTML).

```bash
bsot data format [OPTIONS] DATA
```

---

## auth

Authentication analysis.

### password-analyze

Analyze password strength.

```bash
bsot auth password-analyze [OPTIONS] PASSWORD
```

| Option | Description |
|--------|-------------|
| `--check-breach` | Check against HIBP |

### jwt-decode

Decode and analyze JWT token.

```bash
bsot auth jwt-decode [OPTIONS] TOKEN
```

---

## system

System analysis.

### processes

List and analyze processes.

```bash
bsot system processes [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--suspicious` | Show only suspicious processes |
| `--json` | Output as JSON |

### connections

List network connections.

```bash
bsot system connections [OPTIONS]
```

---

## ir

Incident response.

### collect

Collect forensic artifacts.

```bash
bsot ir collect [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--profile` | Collection profile: `quick`, `standard`, `full` |
| `-o, --output` | Output directory |

### hash-tree

Generate hash tree for evidence integrity.

```bash
bsot ir hash-tree [OPTIONS] PATH
```

### contain

Generate containment commands.

```bash
bsot ir contain [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--block-ip` | IP to block |
| `--disable-user` | User to disable |
| `--platform` | Target platform |

### cf

Cloudflare integration.

```bash
bsot ir cf [COMMAND]
```

| Command | Description |
|---------|-------------|
| `block` | Block IP |
| `unblock` | Unblock IP |
| `list` | List rules |
| `bulk-block` | Bulk block IPs |
| `test` | Test connection |

---

## malware

Malware analysis.

### strings

Extract and categorize strings.

```bash
bsot malware strings [OPTIONS] FILE
```

### pe

Analyze PE file.

```bash
bsot malware pe [OPTIONS] FILE
```

| Option | Description |
|--------|-------------|
| `--sections` | Show section details |
| `--imports` | Show imports |
| `--exports` | Show exports |
| `--json` | Output as JSON |

### yara

Scan with YARA rules.

```bash
bsot malware yara [OPTIONS] FILE
```

| Option | Description |
|--------|-------------|
| `-r, --rules` | Custom rules file |

### deobfuscate

Deobfuscate scripts.

```bash
bsot malware deobfuscate [OPTIONS] FILE
```

### submit

Submit to online sandboxes.

```bash
bsot malware submit [OPTIONS] FILE
```

| Option | Description |
|--------|-------------|
| `--no-upload` | Hash lookup only |

### ioc

Extract IOCs from file.

```bash
bsot malware ioc [OPTIONS] FILE
```

### compare

Compare files (fuzzy hashing).

```bash
bsot malware compare [OPTIONS] FILE1 FILE2
```

---

## report

Reporting and case management.

### case

Case management commands.

| Command | Description |
|---------|-------------|
| `new` | Create new case |
| `list` | List cases |
| `open` | Open case |
| `close` | Close case |
| `add` | Add artifact |
| `note` | Add note |
| `timeline` | Add timeline entry |
| `status` | Show case status |

### generate

Generate report.

```bash
bsot report generate [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--template` | Template: `executive`, `technical`, `ioc`, `timeline` |
| `-o, --output` | Output file |

### ioc

Export IOCs.

```bash
bsot report ioc [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format` | Format: `json`, `csv`, `stix`, `misp` |

### timeline

Export timeline.

```bash
bsot report timeline [OPTIONS]
```

### package

Package case for delivery.

```bash
bsot report package [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--encrypt` | Encrypt package |
| `-o, --output` | Output file |

---

## config

Configuration management.

```bash
bsot config [COMMAND]
```

| Command | Description |
|---------|-------------|
| `show` | Show configuration |
| `set` | Set configuration value |
| `get` | Get configuration value |
| `path` | Show config file path |

---

## cache

Cache management.

```bash
bsot cache [COMMAND]
```

| Command | Description |
|---------|-------------|
| `clear` | Clear cache |
| `stats` | Show cache statistics |

