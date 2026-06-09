# System Module

System monitoring tools for process and network connection analysis.

---

## Overview

The system module provides:

- Running process analysis
- Suspicious process detection
- Network connection monitoring
- Process-to-connection mapping

!!! note "Requirements"
    This module requires the `psutil` library. Install with:
    ```bash
    pip install psutil
    ```

---

## Commands

| Command | Description |
|---------|-------------|
| [`processes`](#bsot-system-processes) | List and analyze running processes |
| [`connections`](#bsot-system-connections) | Show active network connections |

---

## `bsot system processes`

List and analyze running processes, detecting suspicious indicators.

### Usage

```bash
bsot system processes [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--suspicious`, `-s` | flag | `false` | Only show suspicious processes |
| `--json` | flag | `false` | JSON output |

### Detection Criteria

- Known malicious process names
- Processes running from temp directories
- Deleted binaries still running
- Hidden or unusual processes

### Examples

```bash
# List all processes
bsot system processes

# Only suspicious processes
bsot system processes --suspicious

# JSON output
bsot system processes --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Running Processes
    ══════════════════════════════════════════════════════════
      Total: 234
    
    ── Suspicious Processes (2) ──────────────────────────────
    
      [!] PID 12345: svchost.exe
          User: SYSTEM
          Path: C:\Users\Public\svchost.exe
          • Process name mimics Windows system process
          • Running from unusual location
    
      [!] PID 67890: update.exe
          User: jdoe
          Path: /tmp/update.exe
          • Running from temp directory
    
    ── Top Processes by CPU ──────────────────────────────────
    
       PID    CPU%  MEM%  USER          NAME
      ────────────────────────────────────────────────────
      1234    25.3   2.1  jdoe          chrome
      5678    15.2   4.5  root          dockerd
      9012    10.1   1.2  jdoe          code
      ...
    ```

---

## `bsot system connections`

Show active network connections.

### Usage

```bash
bsot system connections [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--suspicious`, `-s` | flag | `false` | Only show suspicious connections |
| `--json` | flag | `false` | JSON output |

!!! note "Permissions"
    May require root/admin privileges on some systems.

### Examples

```bash
# List all connections
bsot system connections

# JSON output
bsot system connections --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Network Connections
    ══════════════════════════════════════════════════════════
      Established: 23
    
      LOCAL                   REMOTE                    PID  PROCESS
      ──────────────────────────────────────────────────────────────
      192.168.1.100:52431    93.184.216.34:443       1234  chrome
      192.168.1.100:52432    172.217.14.99:443       1234  chrome
      192.168.1.100:22       10.0.0.50:55123         5678  sshd
      ...
    ```

---

## Related Commands

- [`bsot ir collect`](ir.md#bsot-ir-collect) — Collect system artifacts including process info

