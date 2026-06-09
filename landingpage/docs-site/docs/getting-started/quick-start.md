# Quick Start

Get up and running with BSOT in 5 minutes.

---

## Prerequisites

- BSOT installed ([Installation Guide](installation.md))
- Optional: API keys configured ([Configuration Guide](configuration.md))

---

## Your First Commands

### 1. Get Help

```bash
# Overall help
bsot --help

# Module help
bsot phishing --help

# Command help
bsot phishing analyze --help
```

### 2. Analyze a File

```bash
# Hash a file
bsot file hash sample.exe

# Identify file type
bsot file identify suspicious.pdf

# Check entropy (packing detection)
bsot file entropy packed.exe
```

### 3. Decode Data

```bash
# Decode base64
echo "aGVsbG8gd29ybGQ=" | bsot data decode -e base64

# Decode URL encoding
bsot data decode -e url "https%3A%2F%2Fexample.com"

# Convert timestamp
bsot data timestamp 1704067200
```

### 4. Check an IP or Domain

```bash
# Enrich an IOC (requires API keys)
bsot intel enrich 8.8.8.8

# WHOIS lookup (no API key needed)
bsot intel whois google.com

# GeoIP lookup
bsot intel geoip 8.8.8.8

# Defang for safe sharing
bsot intel defang "http://malicious.com"
```

### 5. Analyze Network

```bash
# Check SSL certificate
bsot network ssl-check google.com

# Audit HTTP security headers
bsot network headers https://example.com

# Check email security (SPF/DKIM/DMARC)
bsot network dns example.com --all
```

---

## Common Workflows

### Analyze a Suspicious Email

```bash
# Full analysis
bsot phishing analyze email.eml

# Extract IOCs
bsot phishing extract-iocs email.eml

# Check authentication
bsot phishing headers email.eml
```

### Triage a Suspicious File

```bash
# Identify and hash
bsot file identify sample.bin
bsot file hash sample.bin --all

# Check entropy
bsot file entropy sample.bin

# Extract strings
bsot file strings sample.bin
```

### Investigate an IOC

```bash
# Full enrichment
bsot intel enrich suspicious-domain.com

# WHOIS details
bsot intel whois suspicious-domain.com

# DNS records
bsot network dns suspicious-domain.com --all
```

---

## Output Formats

Most commands support JSON output for automation:

```bash
# JSON output
bsot file hash sample.exe --json

# Save to file
bsot intel enrich 8.8.8.8 --json > enrichment.json

# Pipe to jq for processing
bsot file hash sample.exe --json | jq '.sha256'
```

---

## Piping and Scripting

BSOT works great in pipelines:

```bash
# Hash multiple files
for file in *.exe; do
  bsot file hash "$file" --json
done | jq -s '.'

# Bulk enrich IOCs from file
cat iocs.txt | while read ioc; do
  bsot intel enrich "$ioc" --json
done

# Or use the bulk command
bsot intel bulk -f iocs.txt --json
```

---

## What's Next?

Now that you know the basics:

1. **[Configure API keys](configuration.md)** to enable threat intelligence
2. **[Explore modules](../modules/index.md)** to learn all capabilities
3. **[Follow use cases](../use-cases/index.md)** for real-world workflows
4. **[Check examples](../examples/index.md)** for quick reference

---

## Quick Reference

| Task | Command |
|------|---------|
| Analyze email | `bsot phishing analyze email.eml` |
| Hash file | `bsot file hash file.exe` |
| Identify file | `bsot file identify file.bin` |
| Enrich IOC | `bsot intel enrich <ioc>` |
| WHOIS lookup | `bsot intel whois domain.com` |
| SSL check | `bsot network ssl-check domain.com` |
| Decode base64 | `bsot data decode -e base64 <data>` |
| Check password | `bsot auth password-analyze <pass>` |
| List processes | `bsot system processes` |
| Collect evidence | `bsot ir collect` |
