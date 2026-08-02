# BSOT - Blue Security Ops Toolkit

## Project Overview

A comprehensive CLI toolkit for blue team security operations. Analyze phishing emails, enrich IOCs, triage malware, investigate logs, and more—all from your terminal.

## Project Structure

```
SecurityToolbox/
├── bsot.py                          # Main CLI entry point
├── bsot/                            # Core modules
│   ├── cli.py                       # CLI with lazy loading
│   ├── config.py                    # Configuration management
│   ├── cache.py                     # API response caching
│   ├── utils.py                     # Shared utilities
│   │
│   ├── phishing/                    # Phishing analysis
│   ├── intel/                       # Threat intelligence & CVE search
│   ├── file/                        # File analysis
│   ├── network/                     # Network security
│   ├── logs/                        # Log analysis & AI analysis
│   ├── data/                        # Encoding/decoding
│   ├── auth/                        # Authentication analysis
│   ├── system/                      # System monitoring
│   ├── ir/                          # Incident response
│   ├── malware/                     # Malware analysis
│   ├── report/                      # Case management & LLM client
│   └── osint/                       # Open source intelligence
│
├── setup.py                         # pip installation
├── setup_cx.py                      # cx_Freeze build config
├── build.sh                         # Build script
├── requirements.txt                 # Python dependencies
│
├── landingpage/                     # Marketing & docs site
│   ├── marketing/                   # Landing page
│   └── docs-site/                   # MkDocs documentation
│
└── legacy/                          # Old standalone scripts
```

## Command Categories

### Phishing Analysis (`bsot phishing`)
- `analyze` - Full email analysis with AI
- `headers` - Parse email headers
- `extract-iocs` - Extract IOCs from email

### Threat Intelligence (`bsot intel`)
- `enrich` - Enrich IOCs (VirusTotal, AbuseIPDB, etc.)
- `cve` - Search CVEs by keyword or ID
- `whois` - Domain WHOIS lookup
- `geoip` - IP geolocation
- `defang/refang` - IOC defanging

### Log Analysis (`bsot logs`)
- `analyze` - Detect attack patterns
- `timeline` - Build investigative timeline
- `ai-analyze` - AI-powered analysis
- `stats` - Log statistics
- `parse` - Parse and normalize logs

### File Analysis (`bsot file`)
- `hash` - Calculate file hashes
- `identify` - Identify file type
- `strings` - Extract strings
- `entropy` - Calculate entropy
- `secrets` - Find secrets/credentials

### Network Security (`bsot network`)
- `ssl-check` - SSL/TLS analysis
- `dns-check` - DNS security (SPF/DKIM/DMARC)
- `headers` - HTTP security headers

### Data Tools (`bsot data`)
- `decode` - Base64/hex/URL decode
- `encode` - Base64/hex/URL encode
- `timestamp` - Convert timestamps

### Malware Analysis (`bsot malware`)
- `pe` - PE file analysis
- `yara` - YARA scanning
- `strings` - String analysis
- `deobfuscate` - Deobfuscation

### Incident Response (`bsot ir`)
- `collect` - Collect artifacts
- `cf` - Cloudflare containment

### Case Management (`bsot case/report`)
- `new/open/close` - Case lifecycle
- `add-ioc/add-note` - Add evidence
- `generate` - Generate reports

## Installation

### From Source (Development)
```bash
git clone git@github.com:Remillardj/SecurityToolbox.git
cd SecurityToolbox
pip install -e .
bsot --help
```

### Build Binary (Distribution)
```bash
./build.sh

# Install
mkdir -p ~/.local/bin ~/.local/share
cp -r dist/bsot_cx ~/.local/share/bsot
ln -sf ~/.local/share/bsot/bsot ~/.local/bin/bsot
```

## Configuration

API keys via environment variables:
```bash
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
export ANTHROPIC_API_KEY=your_key  # For AI features
```

Or via config file: `~/.bsot/config.json`

## Quick Examples

```bash
# Analyze suspicious email
bsot phishing analyze suspicious.eml

# Search for CVEs
bsot intel cve log4j --minimal
bsot intel cve CVE-2021-44228 -v

# Enrich an IP
bsot intel enrich 1.2.3.4

# Build log timeline
bsot logs timeline -f auth.log --group-by session

# AI-powered log analysis
bsot logs ai-analyze -f auth.log --focus attack

# Check SSL certificate
bsot network ssl-check example.com

# Decode data
bsot data decode base64 "SGVsbG8gV29ybGQ="
```

## Performance

| Method | Startup Time |
|--------|-------------|
| `pip install -e .` | ~0.1s |
| cx_Freeze (first run) | ~1.5s |
| cx_Freeze (cached) | ~0.04s |

## Documentation

- **README.md** - Overview and installation
- **USAGE.md** - Command examples
- **BUILD.md** - Binary build guide
- **landingpage/docs-site/** - Full documentation

## Links

- **Website**: [bluesecurityops.com](https://bluesecurityops.com)
- **GitHub**: [github.com/Remillardj/SecurityToolbox](https://github.com/Remillardj/SecurityToolbox)
