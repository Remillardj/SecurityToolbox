# Examples

Common tasks and command combinations for everyday security work.

---

## Quick Reference

### Email & Phishing

```bash
# Analyze email
bsot phishing analyze suspicious.eml

# Extract IOCs from email
bsot phishing extract-iocs suspicious.eml

# Check email with AI
bsot phishing ai-analyze suspicious.eml --provider openai
```

### File Analysis

```bash
# Hash a file
bsot file hash malware.exe --all

# Identify file type
bsot file identify unknown_file

# Extract strings
bsot file strings binary.exe --min-length 8
```

### IOC Enrichment

```bash
# Enrich single IOC
bsot intel enrich 8.8.8.8

# Bulk enrich from file
bsot intel bulk -f iocs.txt --json

# WHOIS lookup
bsot intel whois suspicious-domain.com
```

### Malware Analysis

```bash
# PE analysis
bsot malware pe sample.exe --sections

# YARA scan
bsot malware yara sample.exe

# Deobfuscate script
bsot malware deobfuscate script.ps1
```

### Network

```bash
# Check SSL certificate
bsot network ssl-check example.com

# Audit HTTP headers
bsot network headers https://example.com

# Check email security
bsot network dns example.com --all
```

### Logs

```bash
# Analyze auth log
bsot logs analyze -f /var/log/auth.log

# Get log statistics
bsot logs stats -f access.log --top-ips 50

# Parse logs
bsot logs parse -f syslog.log
```

### Data Encoding

```bash
# Decode base64
echo "aGVsbG8gd29ybGQ=" | bsot data decode -e base64

# Decode URL
bsot data decode -e url "https%3A%2F%2Fexample.com"

# Convert timestamp
bsot data timestamp 1704067200
```

### System

```bash
# List suspicious processes
bsot system processes --suspicious

# List network connections
bsot system connections
```

### IR & Containment

```bash
# Collect artifacts
bsot ir collect --profile full -o ./evidence

# Block IP at Cloudflare
bsot ir cf block 1.2.3.4 --note "Malicious"

# Generate containment commands
bsot ir contain --block-ip 1.2.3.4 --platform linux
```

### Reporting

```bash
# Create new case
bsot case new phishing-case-001 --type phishing

# Add artifact
bsot case add suspicious.eml

# Generate report
bsot report generate --template executive
```

---

## Pipelines

### Email → IOCs → Enriched Report

```bash
# Extract IOCs, enrich, and save
bsot phishing extract-iocs email.eml --format json | \
  jq -r '.[] | select(.type == "ip" or .type == "domain") | .value' | \
  bsot intel bulk -f - --json > enriched_iocs.json
```

### File → Hash → VirusTotal

```bash
# Hash and check
HASH=$(bsot file hash malware.exe --json | jq -r '.sha256')
bsot intel enrich $HASH
```

### Logs → Findings → Case

```bash
# Analyze and document
bsot logs analyze -f auth.log --json > findings.json
bsot case new log-findings --type intrusion
bsot case add findings.json
```

---

## One-Liners

```bash
# Defang URL for safe sharing
bsot intel defang "http://malicious.com/path"

# Quick password check
bsot auth password-analyze "P@ssw0rd" --check-breach

# Decode JWT
bsot auth jwt-decode "eyJ0eXAi..."

# Convert hex to ASCII
echo "68656c6c6f" | bsot data decode -e hex

# Get GeoIP for IP
bsot intel geoip 8.8.8.8
```

---

## Cheatsheet

| Task | Command |
|------|---------|
| Analyze email | `bsot phishing analyze email.eml` |
| Hash file | `bsot file hash file.exe` |
| Identify file | `bsot file identify file.bin` |
| Enrich IOC | `bsot intel enrich <ioc>` |
| WHOIS | `bsot intel whois domain.com` |
| SSL check | `bsot network ssl-check domain.com` |
| Parse logs | `bsot logs parse -f log.txt` |
| Analyze logs | `bsot logs analyze -f log.txt` |
| Decode base64 | `bsot data decode -e base64 <data>` |
| Check password | `bsot auth password-analyze <pass>` |
| Decode JWT | `bsot auth jwt-decode <token>` |
| List processes | `bsot system processes` |
| Collect evidence | `bsot ir collect` |
| New case | `bsot case new <name>` |
| Generate report | `bsot report generate` |

