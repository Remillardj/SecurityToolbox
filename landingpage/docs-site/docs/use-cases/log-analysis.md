# Log Analysis

Finding attack patterns in authentication and system logs.

---

## Scenario

You need to analyze authentication logs to identify potential security incidents like brute force attacks, password spraying, or unauthorized access.

---

## Step 1: Parse and Understand the Logs

First, parse the log to understand its structure:

```bash
bsot logs parse -f /var/log/auth.log --limit 100
```

??? example "Sample Output"
    ```
    Detected format: syslog
    Events: 100
    
    ── Sample Events (first 5) ───────────────────────────────
    
      Timestamp: Jan 15 14:32:15
      Source IP: 192.168.1.50
      User: admin
      Type: authentication/failure
      Message: Failed password for admin from 192.168.1.50...
    ```

---

## Step 2: Get Statistics

Understand the baseline:

```bash
bsot logs stats -f /var/log/auth.log --top-ips 20 --by-hour
```

??? example "Sample Output"
    ```
    ══════════════════════════════════════════════════════════
      Log Statistics: /var/log/auth.log
    ══════════════════════════════════════════════════════════
      Total Events: 15,234
    
    ── Top 20 Source IPs ─────────────────────────────────────
      203.0.113.50     1,523 (10.0%) ████████████████████
      192.168.1.100      456 ( 3.0%) ██████
      10.0.0.25          234 ( 1.5%) ███
      ...
    
    ── Hourly Distribution ───────────────────────────────────
      00:00   234 ████
      01:00   156 ███
      02:00  1892 ████████████████████████████████
      03:00  2105 ████████████████████████████████████
      04:00   345 █████
      ...
    ```

**Key finding:** Unusual spike at 02:00-03:00, primarily from 203.0.113.50.

---

## Step 3: Detect Attack Patterns

Run attack detection:

```bash
bsot logs analyze -f /var/log/auth.log
```

??? example "Sample Output"
    ```
    ══════════════════════════════════════════════════════════
      Log Analysis Results
    ══════════════════════════════════════════════════════════
      File: /var/log/auth.log
      Events: 15,234
      Time Range: 2025-01-14 00:00:00 - 2025-01-15 23:59:59
    
    ── Findings (4) ──────────────────────────────────────────
    
      [CRITICAL] Brute Force Attack Detected
        Source IP: 203.0.113.50
        MITRE: T1110.001 - Brute Force: Password Guessing
        Target User: admin
        Events: 1,523
        Time: 2025-01-15 02:15 - 03:45
        Evidence:
          • Jan 15 02:15:01 Failed password for admin from 203.0.113.50
          • Jan 15 02:15:02 Failed password for admin from 203.0.113.50
          • Jan 15 02:15:03 Failed password for admin from 203.0.113.50
          • ...
    
      [HIGH] Password Spraying Detected
        Source IP: 198.51.100.25
        MITRE: T1110.003 - Password Spraying
        Pattern: Same password across 45 accounts
        Events: 45
    
      [HIGH] Successful Login After Brute Force
        Source IP: 203.0.113.50
        User: admin
        MITRE: T1078 - Valid Accounts
        Time: 2025-01-15 03:47:22
        Note: Successful login after 1,523 failed attempts
    
      [MEDIUM] Off-Hours SSH Access
        User: contractor
        Time: 03:15:00 UTC
        Note: Access outside business hours (09:00-18:00)
    
    ── Statistics ────────────────────────────────────────────
    
      Authentication:
        Success: 12,847
        Failure: 2,387 (15.7%)
    
      Top Source IPs:
        203.0.113.50: 1,523
        198.51.100.25: 456
    
      Top Targeted Users:
        admin: 1,523
        root: 456
        deploy: 234
    ```

---

## Step 4: Deep Dive on Findings

### Investigate the Attacker IP

```bash
bsot intel enrich 203.0.113.50
```

??? example "Sample Output"
    ```
    ▌ VERDICT: MALICIOUS
    ▌ CONFIDENCE: 95%
    
    📊 Sources: 3 malicious, 0 suspicious
    🌍 Country: Russia
    
    🏷️  Tags: bruteforce, scanner, ssh-scanner
    
    ABUSEIPDB: MALICIOUS
      Abuse Score: 100%
      Reports: 2,847
      Last Reported: 2 hours ago
    ```

### Check if Attack Succeeded

Look for what happened after the successful login:

```bash
grep "admin" /var/log/auth.log | grep "203.0.113.50" | tail -20
```

---

## Step 5: Document Findings

```bash
bsot case new brute-force-attack --type intrusion

bsot case timeline "Brute force attack began" --time "2025-01-15 02:15:00"
bsot case timeline "Attack successful - admin compromised" --time "2025-01-15 03:47:00"
bsot case timeline "Attack detected via log analysis"

bsot case note "Attacker IP 203.0.113.50 conducted brute force against admin"
bsot case note "Attack lasted ~90 minutes with 1,523 attempts"
bsot case note "Attacker succeeded at 03:47 and gained access"
```

---

## Step 6: Export Findings

```bash
# JSON report
bsot logs analyze -f /var/log/auth.log --json -o findings.json

# Generate report
bsot report generate --template technical
```

---

## Common Detection Patterns

### Brute Force Detection

- Many failed logins from single IP
- Targeting single or few accounts
- High rate of attempts

```bash
bsot logs analyze -f auth.log --checks brute_force
```

### Password Spraying Detection

- Single password across many accounts
- Low and slow to avoid lockouts
- Often targets common usernames

```bash
bsot logs analyze -f auth.log --checks password_spray
```

### Privilege Escalation Detection

- Unauthorized sudo attempts
- Service account abuse
- Root access attempts

```bash
bsot logs analyze -f auth.log --checks privesc
```

### Lateral Movement Detection

- SSH between internal hosts
- Unusual authentication patterns
- Access from new sources

```bash
bsot logs analyze -f auth.log --checks lateral
```

---

## Automation

### Daily Log Review

```bash
#!/bin/bash
# daily_log_review.sh

DATE=$(date -d "yesterday" +%Y-%m-%d)
LOG="/var/log/auth.log"

echo "=== Log Analysis for $DATE ==="
bsot logs analyze -f $LOG --json | \
  jq '.findings[] | select(.severity == "critical" or .severity == "high")'
```

### Alert on Findings

```bash
#!/bin/bash
# alert_on_findings.sh

FINDINGS=$(bsot logs analyze -f /var/log/auth.log --json | jq '.findings | length')

if [ "$FINDINGS" -gt 0 ]; then
  echo "⚠️ $FINDINGS security findings detected!"
  bsot logs analyze -f /var/log/auth.log
fi
```

---

## Reference

### Log Formats

| Format | Command | Example |
|--------|---------|---------|
| Syslog | `--format syslog` | Linux auth.log |
| JSON | `--format json` | Structured logs |
| CLF | `--format clf` | Apache/Nginx access |
| CEF | `--format cef` | Security products |
| Auto | `--format auto` | Let BSOT detect |

