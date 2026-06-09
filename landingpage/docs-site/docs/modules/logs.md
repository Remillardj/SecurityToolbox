# Logs Module

Log analysis and attack pattern detection tools.

---

## Overview

The logs module provides:

- Multi-format log parsing (syslog, JSON, CLF, CEF)
- Attack pattern detection (brute force, password spraying, privilege escalation)
- Statistical analysis of log data
- MITRE ATT&CK technique mapping

---

## Commands

| Command | Description |
|---------|-------------|
| [`parse`](#bsot-logs-parse) | Parse and normalize log files |
| [`analyze`](#bsot-logs-analyze) | Detect attack patterns |
| [`stats`](#bsot-logs-stats) | Generate log statistics |

---

## `bsot logs parse`

Parse and normalize log files from various formats.

### Usage

```bash
bsot logs parse -f <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--file`, `-f` | PATH | ✅ | Log file to parse |
| `--format`, `-F` | choice | `auto` | Format: auto, syslog, json, clf, cef |
| `--limit`, `-n` | int | - | Maximum events to parse |
| `--json` | flag | `false` | JSON output |
| `--output`, `-o` | PATH | - | Output file |

### Supported Formats

- **syslog** — Standard syslog format
- **json** — JSON-formatted logs
- **clf** — Common Log Format (Apache/Nginx)
- **cef** — Common Event Format

### Examples

```bash
# Parse with auto-detection
bsot logs parse -f auth.log

# Specify format
bsot logs parse -f access.log --format clf

# Export to JSON
bsot logs parse -f events.json --json -o normalized.json

# Limit events
bsot logs parse -f large.log --limit 1000
```

---

## `bsot logs analyze`

Analyze logs for attack patterns and security issues.

### Usage

```bash
bsot logs analyze -f <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--file`, `-f` | PATH | ✅ | Log file to analyze |
| `--format`, `-F` | string | `auto` | Log format |
| `--checks` | string | `all` | Checks: brute_force,privesc,lateral,anomaly |
| `--mitre` | flag | `true` | Include MITRE ATT&CK IDs |
| `--json` | flag | `false` | JSON output |
| `--output`, `-o` | PATH | - | Output file |

### Detection Capabilities

- **Brute Force** — Multiple failed logins from same source
- **Password Spraying** — Single password across many accounts
- **Privilege Escalation** — Sudo abuse, unauthorized sudo attempts
- **Lateral Movement** — SSH between internal hosts
- **Off-Hours Activity** — Logins outside business hours

### Examples

```bash
# Full analysis
bsot logs analyze -f auth.log

# Specific checks only
bsot logs analyze -f secure.log --checks brute_force,privesc

# JSON output
bsot logs analyze -f events.log --json -o findings.json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Log Analysis Results
    ══════════════════════════════════════════════════════════
    
      File: auth.log
      Events: 15,234
      Time Range: 2025-01-10 00:00:00 - 2025-01-15 23:59:59
    
    ── Findings (3) ──────────────────────────────────────────
    
      [CRITICAL] Brute Force Attack Detected
        Source IP: 203.0.113.50
        MITRE: T1110.001 - Brute Force: Password Guessing
        Target User: admin
        Events: 1,523
        Evidence:
          • Jan 15 14:32:15 Failed password for admin from 203.0.113.50
          • Jan 15 14:32:16 Failed password for admin from 203.0.113.50
          • ...
    
      [HIGH] Privilege Escalation Attempt
        User: jdoe
        MITRE: T1548.003 - Sudo and Sudo Caching
        Events: 5
    
      [MEDIUM] Off-Hours SSH Login
        User: contractor
        Time: 03:42:15 UTC
        Events: 2
    
    ── Statistics ────────────────────────────────────────────
    
      Authentication:
        Success: 12,847
        Failure: 2,387 (15.7%)
    
      Top Source IPs:
        203.0.113.50: 1,523
        192.168.1.100: 456
        10.0.0.25: 234
    ```

---

## `bsot logs stats`

Generate statistics from log files.

### Usage

```bash
bsot logs stats -f <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--file`, `-f` | PATH | ✅ | Log file |
| `--format`, `-F` | string | `auto` | Log format |
| `--top-ips` | int | `10` | Show top N source IPs |
| `--top-users` | int | `10` | Show top N users |
| `--by-hour` | flag | `false` | Show hourly distribution |
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Basic statistics
bsot logs stats -f access.log

# More top entries
bsot logs stats -f auth.log --top-ips 20 --top-users 20

# With hourly breakdown
bsot logs stats -f auth.log --by-hour
```

---

## Related Commands

- [`bsot ir collect`](ir.md#bsot-ir-collect) — Collect system logs

