# IR Module

Incident response and forensics tools including artifact collection, containment, and Cloudflare integration.

---

## Overview

The IR module provides:

- Forensic artifact collection from systems
- Evidence hashing for chain of custody
- Containment command generation
- Cloudflare firewall management for rapid response

---

## Commands

| Command | Description |
|---------|-------------|
| [`collect`](#bsot-ir-collect) | Collect forensic artifacts |
| [`hash-tree`](#bsot-ir-hash-tree) | Hash directory for evidence integrity |
| [`contain`](#bsot-ir-contain) | Generate containment commands |
| [`cf block`](#bsot-ir-cf-block) | Block IP on Cloudflare |
| [`cf unblock`](#bsot-ir-cf-unblock) | Remove Cloudflare block |
| [`cf list`](#bsot-ir-cf-list) | List Cloudflare rules |
| [`cf bulk-block`](#bsot-ir-cf-bulk-block) | Bulk block IPs |
| [`cf test`](#bsot-ir-cf-test) | Test Cloudflare connection |

---

## `bsot ir collect`

Collect forensic artifacts from the system.

### Usage

```bash
bsot ir collect [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--profile`, `-p` | choice | `standard` | Collection profile: quick, standard, full |
| `--output-dir`, `-o` | PATH | - | Output directory |
| `--json` | flag | `false` | JSON manifest output |

### Collection Profiles

| Profile | Artifacts | Time |
|---------|-----------|------|
| **quick** | Processes, network, users | ~30 seconds |
| **standard** | + scheduled tasks, startup items, recent files | ~2 minutes |
| **full** | + installed software, all user accounts | ~5 minutes |

### Examples

```bash
# Standard collection
bsot ir collect

# Quick collection
bsot ir collect --profile quick

# Full collection to specific directory
bsot ir collect --profile full -o ./evidence
```

---

## `bsot ir hash-tree`

Hash all files in a directory for evidence integrity verification.

### Usage

```bash
bsot ir hash-tree <path> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--algorithm`, `-a` | string | `sha256` | Hash algorithm |
| `--output`, `-o` | PATH | - | Output manifest file |
| `--json` | flag | `false` | JSON output to stdout |

### Examples

```bash
# Create evidence manifest
bsot ir hash-tree ./evidence

# Specify output file
bsot ir hash-tree ./evidence -o manifest.json

# JSON output
bsot ir hash-tree ./evidence --json
```

---

## `bsot ir contain`

Generate containment commands (does NOT execute them).

### Usage

```bash
bsot ir contain [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--block-ip` | string | Generate command to block IP |
| `--block-domain` | string | Generate command to block domain |
| `--disable-user` | string | Generate command to disable user |
| `--platform` | choice | Target: auto, linux, macos, windows |

!!! warning "Safety First"
    This command only **generates** commands for review. It does not execute them. Always verify commands before running manually.

### Examples

```bash
# Block an IP
bsot ir contain --block-ip 203.0.113.50

# Disable a user account
bsot ir contain --disable-user malicious_user

# Specify platform
bsot ir contain --block-ip 1.2.3.4 --platform linux
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Containment Commands
    ══════════════════════════════════════════════════════════
      Platform: linux
    
      ⚠️  These commands are for review only.
         Execute them manually after verification.
    
    ── Block IP: 203.0.113.50 ────────────────────────────────
    
      # Block IP with iptables
      sudo iptables -A INPUT -s 203.0.113.50 -j DROP
      sudo iptables -A OUTPUT -d 203.0.113.50 -j DROP
    
      # Rollback:
      sudo iptables -D INPUT -s 203.0.113.50 -j DROP
      sudo iptables -D OUTPUT -d 203.0.113.50 -j DROP
    ```

---

## Cloudflare Commands

The `cf` subgroup provides Cloudflare firewall management for rapid incident response.

### Configuration

Set these environment variables:

```bash
export CLOUDFLARE_API_TOKEN="your-token"
export CLOUDFLARE_ZONE_ID="your-zone-id"
# or
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
```

### `bsot ir cf block`

Block an IP address on Cloudflare.

```bash
# Block an IP
bsot ir cf block 203.0.113.50

# With a note
bsot ir cf block 203.0.113.50 --note "C2 server"

# Challenge instead of block
bsot ir cf block 203.0.113.50 --mode challenge

# Block a CIDR range
bsot ir cf block 203.0.113.0/24
```

### `bsot ir cf unblock`

Remove a block rule.

```bash
bsot ir cf unblock <rule_id>
```

### `bsot ir cf list`

List current access rules.

```bash
# List all rules
bsot ir cf list

# Filter by mode
bsot ir cf list --mode block

# Search for IP
bsot ir cf list --search 203.0.113
```

### `bsot ir cf bulk-block`

Block multiple IPs from a file.

```bash
# Block IPs from file
bsot ir cf bulk-block -f malicious_ips.txt

# With note
bsot ir cf bulk-block -f iocs.txt --note "Campaign X"
```

### `bsot ir cf test`

Test Cloudflare API connection.

```bash
bsot ir cf test
```

---

## Workflow Example

Incident response workflow:

```bash
# 1. Create investigation case
bsot case new compromised-host --type intrusion --severity critical

# 2. Collect artifacts
bsot ir collect --profile full -o ./evidence

# 3. Hash evidence for chain of custody
bsot ir hash-tree ./evidence -o evidence_manifest.json

# 4. Block attacker IP immediately
bsot ir cf block 203.0.113.50 --note "Attacker IP from incident"

# 5. Analyze logs
bsot logs analyze -f ./evidence/auth.log

# 6. Generate report
bsot report generate --template technical
```

---

## Related Commands

- [`bsot case new`](report.md#bsot-case-new) — Create investigation case
- [`bsot logs analyze`](logs.md#bsot-logs-analyze) — Analyze collected logs

