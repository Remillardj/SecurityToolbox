# Report Module

Case management, report generation, and evidence export.

---

## Overview

The report module provides:

- Investigation case management
- AI-powered report generation
- IOC export in multiple formats (JSON, CSV, STIX, MISP)
- Timeline management
- Evidence packaging for archival

---

## Case Management Commands

| Command | Description |
|---------|-------------|
| [`case new`](#bsot-case-new) | Create a new investigation case |
| [`case list`](#bsot-case-list) | List all cases |
| [`case open`](#bsot-case-open) | Switch to an existing case |
| [`case close`](#bsot-case-close) | Close the current case |
| [`case add`](#bsot-case-add) | Add an artifact to the case |
| [`case note`](#bsot-case-note) | Add a note |
| [`case timeline`](#bsot-case-timeline) | Manage timeline events |
| [`case status`](#bsot-case-status) | Show case summary |

## Report Commands

| Command | Description |
|---------|-------------|
| [`report generate`](#bsot-report-generate) | Generate incident report |
| [`report ioc`](#bsot-report-ioc) | Export IOCs |
| [`report timeline`](#bsot-report-timeline) | Export timeline |
| [`report package`](#bsot-report-package) | Package case for archival |
| [`report template`](#bsot-report-template) | Manage report templates |

---

## `bsot case new`

Create a new investigation case.

### Usage

```bash
bsot case new <name> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--type`, `-t` | choice | `general` | Case type: general, phishing, malware, intrusion, insider, apt |
| `--description`, `-d` | string | - | Case description |
| `--analyst`, `-a` | string | - | Analyst name |
| `--severity`, `-s` | choice | `medium` | Severity: low, medium, high, critical |
| `--tags` | string | - | Comma-separated tags |

### Examples

```bash
# Simple case
bsot case new phishing-2025-01-15

# With details
bsot case new "Emotet Investigation" --type malware --severity high

# Full options
bsot case new supply-chain-compromise \
  --type apt \
  --severity critical \
  --analyst "Jane Doe" \
  --tags "apt,supply-chain,urgent"
```

---

## `bsot case list`

List all cases.

```bash
# List all cases
bsot case list

# Filter by status
bsot case list --status active

# Recent cases
bsot case list --recent 10
```

---

## `bsot case open`

Switch to an existing case.

```bash
bsot case open phishing-2025-01-15
```

---

## `bsot case add`

Add an artifact to the current case.

```bash
# Add email
bsot case add suspicious.eml

# Add malware sample
bsot case add malware.exe --type malware

# Add screenshot
bsot case add evidence.png --type screenshot
```

---

## `bsot case note`

Add investigation notes.

```bash
# Add a note
bsot case note "User jdoe reported phishing at 09:15 AM"

# View all notes
bsot case note --list
```

---

## `bsot case timeline`

Manage investigation timeline.

```bash
# Add event with current time
bsot case timeline "User clicked malicious link"

# Add event with specific time
bsot case timeline "Phishing email received" --time "2025-01-15 09:00:00"

# View timeline
bsot case timeline --list
```

---

## `bsot case status`

Show current case summary.

```bash
bsot case status
```

??? example "Sample Output"

    ```
    📁 Case: phishing-2025-01-15
       Status: active
       Type: phishing
       Severity: high
       Created: 2025-01-15T10:30:00Z
       Analyst: Jane Doe
    
    📊 Artifacts
       Email: 2
       Malware: 1
       Screenshot: 3
    
    🔍 Analysis Outputs
       Phishing analyses: 2
       Intel enrichments: 5
    
    🎯 IOCs: 15
       ip: 3 | domain: 5 | url: 7
    
    📝 Notes: 8 entries
    📅 Timeline: 12 events
    ```

---

## `bsot report generate`

Generate an AI-powered incident report.

### Usage

```bash
bsot report generate [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--template`, `-t` | choice | `technical` | Template: executive, technical, ioc, timeline |
| `--audience`, `-a` | string | - | Target audience (overrides template) |
| `--format`, `-f` | choice | `markdown` | Output: markdown, html |
| `--llm`, `-l` | choice | - | LLM provider: anthropic, openai, ollama |
| `--no-llm` | flag | `false` | Generate without AI |
| `--output`, `-o` | PATH | - | Output file path |

### Templates

| Template | Description | Sections |
|----------|-------------|----------|
| **executive** | High-level summary for management | Summary, impact, recommendations |
| **technical** | Detailed technical analysis | Full IOCs, timeline, methodology |
| **ioc** | IOC-focused report | IOCs with context |
| **timeline** | Chronological narrative | Timeline-based structure |

### Examples

```bash
# Generate with defaults
bsot report generate

# Executive summary
bsot report generate --template executive

# HTML output
bsot report generate --format html -o report.html

# Use Ollama for local LLM
bsot report generate --llm ollama

# Without AI
bsot report generate --no-llm
```

---

## `bsot report ioc`

Export IOCs from the current case.

### Usage

```bash
bsot report ioc [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--format`, `-f` | choice | `json` | Format: json, csv, stix, misp |
| `--type`, `-t` | string | - | Filter by type (comma-separated) |
| `--confidence`, `-c` | choice | - | Filter by confidence: low, medium, high |
| `--output`, `-o` | PATH | - | Output file |

### Examples

```bash
# Export as JSON
bsot report ioc

# Export as STIX 2.1
bsot report ioc --format stix -o iocs.stix.json

# Export as CSV
bsot report ioc --format csv -o iocs.csv

# Export for MISP
bsot report ioc --format misp -o misp_event.json

# Filter by type
bsot report ioc --type ip,domain --format csv
```

---

## `bsot report timeline`

Export investigation timeline.

```bash
# Table format
bsot report timeline

# Markdown
bsot report timeline --format markdown -o timeline.md

# ASCII art
bsot report timeline --format ascii
```

---

## `bsot report package`

Package case for archival or sharing.

### Usage

```bash
bsot report package [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output`, `-o` | PATH | - | Output ZIP path |
| `--exclude-samples` | flag | `false` | Exclude malware samples |
| `--encrypt` | flag | `false` | Encrypt package |
| `--password`, `-p` | string | - | Encryption password |

### Examples

```bash
# Create package
bsot report package

# Exclude malware samples
bsot report package --exclude-samples

# Encrypted package
bsot report package --encrypt --password "secure123"
```

---

## Workflow Example

Complete investigation workflow:

```bash
# Start case
bsot case new phishing-attack --type phishing

# Add evidence
bsot case add suspicious.eml
bsot case add attachment.exe --type malware

# Analyze
bsot phishing analyze suspicious.eml
bsot malware strings attachment.exe

# Document findings
bsot case note "Confirmed credential harvesting attack"
bsot case timeline "User received phishing email" --time "2025-01-15 09:00"
bsot case timeline "User clicked link" --time "2025-01-15 09:05"
bsot case timeline "Credentials harvested" --time "2025-01-15 09:06"

# Generate report
bsot report generate --template executive

# Export IOCs
bsot report ioc --format stix -o iocs.stix.json

# Package for archival
bsot report package --encrypt
```

---

## Related Commands

- [`bsot ir collect`](ir.md#bsot-ir-collect) — Collect forensic artifacts
- [`bsot phishing analyze`](phishing.md#bsot-phishing-analyze) — Analyze phishing emails

