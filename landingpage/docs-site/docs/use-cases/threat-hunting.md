# Threat Hunting

Proactive searching for threats in your environment.

---

## Scenario

You've received threat intelligence about a new campaign targeting organizations in your industry. Time to hunt for indicators in your environment.

---

## Step 1: Gather Intelligence

Start with the IOCs from the threat report:

```bash
# Create hunting case
bsot case new threat-hunt-campaign-x --type apt

# Add IOC list as artifact
bsot case add campaign_iocs.txt
```

---

## Step 2: Enrich IOCs

Validate and enrich the threat intel:

```bash
# Bulk enrich all IOCs
bsot intel bulk -f campaign_iocs.txt --progress --json -o enriched_iocs.json
```

??? example "Sample Output"
    ```
    📋 Loaded 45 IOCs from campaign_iocs.txt
    
    📊 Results Summary:
      Malicious: 32
      Suspicious: 8
      Clean: 3
      Unknown: 2
    
    🚨 Malicious IOCs:
      • 45.33.32.156 (ip)
      • 185.234.72.45 (ip)
      • evil-campaign.xyz (domain)
      • update-service.net (domain)
      ...
    ```

---

## Step 3: Search Logs

Check authentication logs for suspicious activity:

```bash
# Analyze auth logs for known IOCs
bsot logs analyze -f /var/log/auth.log --checks brute_force,anomaly
```

Search for specific IPs:

```bash
# Using grep to find IOC hits in logs
grep -f ips.txt /var/log/*.log
```

---

## Step 4: Network Analysis

Check DNS logs for domain IOCs:

```bash
# Check for DNS queries to malicious domains
bsot network dns evil-campaign.xyz
```

---

## Step 5: File System Checks

Search for IOC file hashes:

```bash
# Hash all executables in suspected directory
bsot file hash /tmp/*.exe -r --json | \
  jq '.[] | select(.sha256 == "known_bad_hash")'
```

---

## Step 6: Process Analysis

Check for suspicious processes:

```bash
bsot system processes --suspicious
```

Check network connections:

```bash
bsot system connections
```

---

## Step 7: Document Findings

```bash
bsot case note "No hits for campaign IOCs in authentication logs"
bsot case note "DNS logs clean - no queries to known C2 domains"
bsot case note "No matching file hashes found on sampled systems"
```

---

## Step 8: Report

Generate hunt report:

```bash
bsot report generate --template technical -o hunt_report.md
```

---

## Hunting Queries Reference

### By IOC Type

```bash
# IP addresses
bsot intel enrich <ip>

# Domains
bsot intel whois <domain>
bsot network dns <domain>

# File hashes
bsot malware submit <file> --no-upload

# URLs
bsot intel defang <url>  # For safe documentation
```

### Log Hunting

```bash
# Failed logins
bsot logs analyze -f auth.log --checks brute_force

# All attack patterns
bsot logs analyze -f auth.log

# Statistics
bsot logs stats -f access.log --top-ips 50
```

### File Hunting

```bash
# Hash directory
bsot file hash /path/to/check -r --json

# Check entropy (packed files)
bsot file entropy suspicious.exe

# Find executables with PDF extension
bsot file identify *.pdf
```

---

## Automation

### Bulk IOC Check Script

```bash
#!/bin/bash
# hunt.sh - Check IOCs against multiple sources

IOC_FILE=$1

echo "=== Enriching IOCs ==="
bsot intel bulk -f $IOC_FILE --json -o enriched.json

echo "=== Checking Malicious ==="
jq '.[] | select(.verdict == "malicious")' enriched.json

echo "=== Generating Report ==="
bsot report generate --template ioc
```

### Daily Hunt

```bash
#!/bin/bash
# daily_hunt.sh

# Analyze yesterday's logs
bsot logs analyze -f /var/log/auth.log --json -o findings.json

# Alert on high severity
jq '.findings[] | select(.severity == "critical" or .severity == "high")' findings.json
```

