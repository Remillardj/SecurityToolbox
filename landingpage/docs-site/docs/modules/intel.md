# Intel Module

Threat intelligence lookups and IOC enrichment from multiple sources.

---

## Overview

The intel module provides:

- Multi-source IOC enrichment (VirusTotal, AbuseIPDB, GreyNoise, OTX, IPInfo)
- Automatic IOC type detection (IP, domain, URL, hash)
- WHOIS lookups with suspicious domain detection
- IP geolocation and network context
- Bulk enrichment for large IOC lists
- IOC defanging and refanging utilities

---

## Commands

| Command | Description |
|---------|-------------|
| [`enrich`](#bsot-intel-enrich) | Enrich a single IOC |
| [`bulk`](#bsot-intel-bulk) | Bulk IOC enrichment from file |
| [`whois`](#bsot-intel-whois) | WHOIS lookup for domains |
| [`geoip`](#bsot-intel-geoip) | IP geolocation |
| [`defang`](#bsot-intel-defang) | Defang an IOC |
| [`refang`](#bsot-intel-refang) | Refang a defanged IOC |

---

## `bsot intel enrich`

Enrich a single IOC against multiple threat intelligence sources.

### Usage

```bash
bsot intel enrich <ioc> [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `ioc` | string | ✅ | IOC to enrich (IP, domain, URL, or hash) |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--sources`, `-s` | string | `all` | Comma-separated sources or "all" |
| `--json` | flag | `false` | JSON output |
| `--output`, `-o` | PATH | - | Write results to file |
| `--no-cache` | flag | `false` | Skip cache |

### Available Sources

- `vt` — VirusTotal
- `abuseipdb` — AbuseIPDB
- `greynoise` — GreyNoise
- `otx` — AlienVault OTX
- `ipinfo` — IPInfo

### Examples

```bash
# Enrich an IP address
bsot intel enrich 45.33.32.156

# Enrich a domain
bsot intel enrich evil-domain.com

# Use specific sources only
bsot intel enrich 1.2.3.4 --sources vt,abuseipdb

# Output as JSON
bsot intel enrich 1.2.3.4 --json

# Skip cache
bsot intel enrich 1.2.3.4 --no-cache
```

??? example "Sample Output"

    ```
    🔍 Enriching ip: 45.33.32.156
       Sources: virustotal, abuseipdb, greynoise, ipinfo
    
    ══════════════════════════════════════════════════════════
      Enrichment Results
    ══════════════════════════════════════════════════════════
    
      ▌ VERDICT: MALICIOUS
      ▌ CONFIDENCE: 85%
    
      📊 Sources: 2 malicious, 1 suspicious, 1 clean
      🌍 Country: Russia
      🏢 ASN: AS12345 Evil Hosting Inc
    
      🏷️  Tags: botnet, scanner, bruteforce
      🦠 Malware: Mirai, Emotet
    
    ── Source Details ────────────────────────────────────────
    
      VIRUSTOTAL: MALICIOUS
        Detection: 15/90
        Link: https://virustotal.com/gui/ip-address/45.33.32.156
    
      ABUSEIPDB: MALICIOUS
        Abuse Score: 100%
        Reports: 1,234
    
      GREYNOISE: SUSPICIOUS
        Classification: malicious
        Noise: Yes (internet background noise)
    
      IPINFO: CLEAN
        Location: Moscow, Russia
        Org: Evil Hosting Inc
        Flags: Datacenter
    ```

---

## `bsot intel bulk`

Bulk IOC enrichment from a file.

### Usage

```bash
bsot intel bulk -f <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--file`, `-f` | PATH | ✅ | File with IOCs (one per line) |
| `--sources`, `-s` | string | `all` | Comma-separated sources |
| `--json` | flag | `false` | JSON output |
| `--csv` | flag | `false` | CSV output |
| `--output`, `-o` | PATH | - | Output file |
| `--max-concurrent` | int | `5` | Parallel requests |
| `--progress` | flag | `false` | Show progress bar |

### Examples

```bash
# Basic bulk enrichment
bsot intel bulk -f iocs.txt

# Output as CSV
bsot intel bulk -f iocs.txt --csv -o results.csv

# With progress bar
bsot intel bulk -f iocs.txt --progress

# JSON output
bsot intel bulk -f iocs.txt --json -o results.json
```

---

## `bsot intel whois`

WHOIS lookup for domain registration information.

### Usage

```bash
bsot intel whois <domain> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Basic WHOIS lookup
bsot intel whois example.com

# Check a suspicious domain
bsot intel whois evil-phishing-site.xyz

# JSON output
bsot intel whois example.com --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      WHOIS: evil-phishing.xyz
    ══════════════════════════════════════════════════════════
    
    ── Registrar ─────────────────────────────────────────────
      Namecheap, Inc.
    
    ── Dates ─────────────────────────────────────────────────
      Created:  2025-01-10
      Expires:  2026-01-10
      Updated:  2025-01-10
      Age:      5 days
      Expires in: 360 days
    
      [HIGH] Domain is only 5 days old - may be suspicious
    
    ── Nameservers ───────────────────────────────────────────
      • dns1.namecheaphosting.com
      • dns2.namecheaphosting.com
    
    ── Registrant ────────────────────────────────────────────
      🔒 WHOIS Privacy Protection: Enabled
    
    ── Suspicious Indicators ─────────────────────────────────
      [MEDIUM] Domain registered less than 30 days ago
      [MEDIUM] Privacy protection enabled
      [LOW] Uses budget registrar
    ```

---

## `bsot intel geoip`

IP geolocation and network context.

### Usage

```bash
bsot intel geoip <ip> [OPTIONS]
```

### Examples

```bash
# Basic lookup
bsot intel geoip 8.8.8.8

# JSON output
bsot intel geoip 1.2.3.4 --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      GeoIP: 8.8.8.8
    ══════════════════════════════════════════════════════════
    
    ── Location ──────────────────────────────────────────────
      Country: United States (US)
      Region:  California
      City:    Mountain View
      Coords:  37.4056,-122.0775
      Timezone: America/Los_Angeles
    
    ── Network ───────────────────────────────────────────────
      Org: Google LLC
      ASN: AS15169
      Hostname: dns.google
    ```

---

## `bsot intel defang`

Defang an IOC for safe sharing in reports and communications.

### Usage

```bash
bsot intel defang <ioc>
```

### Examples

```bash
# Defang a URL
bsot intel defang "https://evil.com/malware"
# Output: hxxps://evil[.]com/malware

# Defang an IP
bsot intel defang 1.2.3.4
# Output: 1[.]2[.]3[.]4

# From stdin
echo "evil.com" | bsot intel defang -
```

---

## `bsot intel refang`

Refang a defanged IOC back to its original form.

### Usage

```bash
bsot intel refang <ioc>
```

### Examples

```bash
# Refang a URL
bsot intel refang "hxxps://evil[.]com"
# Output: https://evil.com

# Refang an IP
bsot intel refang "1[.]2[.]3[.]4"
# Output: 1.2.3.4
```

---

## Configuration

### API Keys

Set API keys via environment variables:

```bash
export VIRUSTOTAL_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export GREYNOISE_API_KEY="your-key"
export OTX_API_KEY="your-key"
export IPINFO_API_KEY="your-key"
```

Or via the config command:

```bash
bsot config set virustotal_api_key "your-key"
```

### Caching

Results are cached by default. Manage the cache with:

```bash
# View cache stats
bsot cache stats

# Clear intel cache
bsot cache clear --service intel
```

---

## Related Commands

- [`bsot phishing analyze`](phishing.md#bsot-phishing-analyze) — Analyze emails and extract IOCs
- [`bsot malware ioc`](malware.md#bsot-malware-ioc) — Extract IOCs from malware

