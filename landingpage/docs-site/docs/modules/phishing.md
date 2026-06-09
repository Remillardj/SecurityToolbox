# Phishing Module

Tools for analyzing suspicious emails, extracting IOCs, and investigating email-based attacks.

---

## Overview

The phishing module helps you:

- Analyze email headers for authentication failures and origin tracing
- Extract URLs, attachments, and other IOCs from email bodies
- Identify common phishing indicators
- Use AI to detect social engineering tactics
- Check IOC reputation against threat intelligence sources
- Prepare evidence for incident reports

---

## Commands

| Command | Description |
|---------|-------------|
| [`analyze`](#bsot-phishing-analyze) | Full email analysis with IOC extraction |
| [`extract-iocs`](#bsot-phishing-extract-iocs) | Extract IOCs from an email |
| [`headers`](#bsot-phishing-headers) | Analyze email headers |
| [`ai-analyze`](#bsot-phishing-ai-analyze) | AI-powered phishing detection |
| [`reputation`](#bsot-phishing-reputation) | Check IOC reputation |

---

## `bsot phishing analyze`

Comprehensive email analysis including parsing, IOC extraction, authentication checks, and optional AI analysis.

### Usage

```bash
bsot phishing analyze <email_file> [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `email_file` | PATH | ✅ | Path to .eml or .msg email file |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--quick`, `-q` | flag | `false` | Quick mode - skip API calls |
| `--output`, `-o` | PATH | - | Export report to file |
| `--format`, `-f` | choice | `json` | Output format: `json` or `html` |
| `--json` | flag | `false` | Output raw JSON to stdout |
| `--verbose`, `-v` | flag | `false` | Show detailed analysis |
| `--openai-key` | string | env | OpenAI API key for AI analysis |
| `--anthropic-key` | string | env | Anthropic API key |
| `--virustotal-key` | string | env | VirusTotal API key |
| `--abuseipdb-key` | string | env | AbuseIPDB API key |
| `--llm-provider` | choice | `openai` | LLM provider: `openai` or `anthropic` |

### Examples

#### Basic Analysis

Quickly analyze an email to see key indicators:

```bash
bsot phishing analyze suspicious.eml
```

??? example "Sample Output"

    ```
    📧 Phishing Analysis: suspicious.eml
    
    ┌─────────────────────────────────────────────────────────┐
    │ Risk Score: HIGH (8/10)                                 │
    ├─────────────────────────────────────────────────────────┤
    │ From:    "IT Support" <support@amaz0n-secure.com>       │
    │ To:      victim@company.com                             │
    │ Subject: Urgent: Verify your account                    │
    │ Date:    2025-01-15 09:15:32 UTC                        │
    └─────────────────────────────────────────────────────────┘
    
    ⚠️  Authentication Failures
        SPF:   FAIL (sender not authorized for domain)
        DKIM:  FAIL (signature verification failed)
        DMARC: FAIL (policy: reject)
    
    🔗 URLs Found (2)
        ⚠️  hxxps://amaz0n-secure[.]com/login?id=abc123
            └─ Suspicious: Typosquatting detected
        ✓  https://amazon.com/help
            └─ Legitimate Amazon domain
    
    📎 Attachments (1)
        invoice_12345.pdf (47.3 KB)
        └─ Type: application/pdf
        └─ SHA256: a1b2c3d4e5f6...
        └─ ⚠️  Contains embedded JavaScript
    
    📋 Extracted IOCs
        Domains: amaz0n-secure.com
        URLs:    hxxps://amaz0n-secure[.]com/login?id=abc123
        IPs:     45.33.32.156 (resolved from amaz0n-secure.com)
    ```

#### Quick Analysis (No API Calls)

Skip reputation checks for faster results:

```bash
bsot phishing analyze suspicious.eml --quick
```

#### Export as HTML Report

Generate a formatted HTML report:

```bash
bsot phishing analyze suspicious.eml -o report.html -f html
```

#### JSON Output for Automation

Get machine-readable output:

```bash
bsot phishing analyze suspicious.eml --json
```

??? example "JSON Output"

    ```json
    {
      "file": "suspicious.eml",
      "risk_score": 8,
      "risk_level": "high",
      "headers": {
        "from": "support@amaz0n-secure.com",
        "to": "victim@company.com",
        "subject": "Urgent: Verify your account",
        "date": "2025-01-15T09:15:32Z"
      },
      "authentication": {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail"
      },
      "iocs": {
        "urls": ["https://amaz0n-secure.com/login?id=abc123"],
        "domains": ["amaz0n-secure.com"],
        "ips": ["45.33.32.156"]
      },
      "attachments": [
        {
          "filename": "invoice_12345.pdf",
          "size": 48435,
          "sha256": "a1b2c3d4e5f6...",
          "suspicious": true
        }
      ]
    }
    ```

#### With Full AI Analysis

Use LLM to analyze social engineering tactics:

```bash
bsot phishing analyze suspicious.eml --llm-provider openai
```

#### Verbose Mode

Get detailed output including raw headers:

```bash
bsot phishing analyze suspicious.eml --verbose
```

### Tips

!!! tip "Best Practices"
    - Always analyze emails in a safe environment (sandbox or isolated VM)
    - Use `--quick` for initial triage, then full analysis for confirmed threats
    - Failed SPF/DKIM/DMARC almost always indicates spoofing
    - Check for typosquatting in sender domains (e.g., `amaz0n` vs `amazon`)

!!! warning "Handle with Care"
    Don't open attachments or click links directly. Use BSOT to safely extract and analyze them.

---

## `bsot phishing extract-iocs`

Extract IOCs (URLs, IPs, domains, hashes) from an email without full analysis.

### Usage

```bash
bsot phishing extract-iocs <email_file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--include-safe` | flag | `false` | Include known safe domains |
| `--json` | flag | `false` | Output as JSON |

### Examples

```bash
# Extract IOCs
bsot phishing extract-iocs suspicious.eml

# Include safe domains (normally filtered)
bsot phishing extract-iocs suspicious.eml --include-safe

# JSON output
bsot phishing extract-iocs suspicious.eml --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Extracted IOCs
    ══════════════════════════════════════════════════════════
    
      Total IOCs found: 7
    
    ── URLs (2) ──────────────────────────────────────────────
      • hxxps://amaz0n-secure[.]com/login?id=abc123
      • hxxps://bit[.]ly/3xYz123
    
    ── Domains (1) ───────────────────────────────────────────
      • amaz0n-secure.com
    
    ── IP Addresses (1) ──────────────────────────────────────
      • 45.33.32.156
    
    ── Email Addresses (2) ───────────────────────────────────
      • support@amaz0n-secure.com
      • noreply@amaz0n-secure.com
    
    ── SHA256 Hashes (1) ─────────────────────────────────────
      • a1b2c3d4e5f6...
    ```

---

## `bsot phishing headers`

Analyze email headers for authentication status and routing information.

### Usage

```bash
bsot phishing headers <email_file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--json` | flag | `false` | Output as JSON |

### Examples

```bash
# Analyze headers
bsot phishing headers suspicious.eml

# JSON output
bsot phishing headers suspicious.eml --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Email Header Analysis
    ══════════════════════════════════════════════════════════
    
    ── Authentication ────────────────────────────────────────
      SPF:   FAIL
      DKIM:  FAIL
      DMARC: FAIL
      Score: 0/100
    
    ── Sender Information ────────────────────────────────────
      Header From:   support@amaz0n-secure.com
      Envelope From: bounce@mail-server.evil.com
      Reply-To:      support@amaz0n-secure.com
    
      [HIGH] From domain mismatch detected!
    
    ── Routing ───────────────────────────────────────────────
      Mail hops:     3
      Transit time:  4s
    
    ── Issues Found ──────────────────────────────────────────
      [HIGH] Envelope From domain doesn't match Header From
      [MEDIUM] Email routed through unusual mail server
    ```

---

## `bsot phishing ai-analyze`

Use AI/LLM to analyze email content for phishing indicators and social engineering tactics.

### Usage

```bash
bsot phishing ai-analyze <email_file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--openai-key` | string | env | OpenAI API key |
| `--anthropic-key` | string | env | Anthropic API key |
| `--provider` | choice | `openai` | LLM provider |
| `--json` | flag | `false` | Output as JSON |

### Examples

```bash
# With OpenAI
bsot phishing ai-analyze suspicious.eml

# With Anthropic
bsot phishing ai-analyze suspicious.eml --provider anthropic

# Using environment variables
OPENAI_API_KEY=sk-xxx bsot phishing ai-analyze suspicious.eml
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      AI Phishing Analysis
    ══════════════════════════════════════════════════════════
    
      Verdict: PHISHING
      Confidence: 94%
      Model: gpt-4
    
    ── Summary ───────────────────────────────────────────────
      This email exhibits multiple indicators of a credential
      harvesting phishing attack impersonating Amazon.
    
    ── Social Engineering Tactics ────────────────────────────
      [HIGH] Urgency: "Account will be suspended in 24 hours"
      [HIGH] Authority: Impersonates IT Support department
      [HIGH] Fear: Threatens account suspension
    
    ── Impersonation Indicators ──────────────────────────────
      [HIGH] Domain typosquatting: amaz0n-secure.com
      [HIGH] Sender name spoofing: "Amazon Support"
    
    ── Pressure/Urgency Tactics ──────────────────────────────
      [MEDIUM] Time pressure: "Immediate action required"
      [MEDIUM] Threat of consequences: "Access will be revoked"
    
    ── Recommendations ───────────────────────────────────────
      1. Do not click any links in this email
      2. Report to your security team immediately
      3. If credentials were entered, reset passwords now
      4. Check account for unauthorized access
    ```

---

## `bsot phishing reputation`

Check the reputation of IOCs found in an email against threat intelligence sources.

### Usage

```bash
bsot phishing reputation <email_file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--virustotal-key` | string | env | VirusTotal API key |
| `--abuseipdb-key` | string | env | AbuseIPDB API key |
| `--max-iocs` | int | `10` | Max IOCs to check per type |
| `--json` | flag | `false` | Output as JSON |

### Examples

```bash
# Check reputation with VirusTotal
bsot phishing reputation suspicious.eml

# Limit IOCs checked
bsot phishing reputation suspicious.eml --max-iocs 5

# JSON output
bsot phishing reputation suspicious.eml --json
```

---

## Workflow Example

Complete phishing investigation from email to report:

```bash
# Step 1: Initial analysis
bsot phishing analyze suspicious.eml

# Step 2: Create investigation case
bsot case new phishing-2025-01-15 --type phishing

# Step 3: Add email as artifact
bsot case add suspicious.eml

# Step 4: Extract and analyze attachments
bsot malware strings ./attachments/invoice.pdf

# Step 5: Enrich IOCs
bsot intel enrich 45.33.32.156
bsot intel enrich amaz0n-secure.com

# Step 6: Document findings
bsot case note "Confirmed credential harvesting phishing attack"
bsot case timeline "Phishing email received by user" --time "2025-01-15 09:15:00"

# Step 7: Generate report
bsot report generate --template executive
```

---

## Related Commands

- [`bsot intel enrich`](intel.md#bsot-intel-enrich) — Enrich extracted IOCs
- [`bsot malware strings`](malware.md#bsot-malware-strings) — Analyze extracted attachments
- [`bsot case new`](report.md#bsot-case-new) — Create investigation case
- [`bsot report generate`](report.md#bsot-report-generate) — Generate incident report

---

## See Also

- [Phishing Investigation Use Case](../use-cases/phishing-investigation.md) — Full walkthrough

