# Phishing Investigation

A complete walkthrough of investigating a reported phishing email.

---

## Scenario

A user forwards a suspicious email to the security team. The email claims to be from "IT Support" and asks the user to verify their account credentials.

**What we'll cover:**

1. Initial analysis of the email
2. Deep dive into headers and IOCs
3. Checking threat intelligence
4. Analyzing attachments
5. Documenting findings
6. Generating a report

---

## Step 1: Create a Case

Start by creating an investigation case to track all evidence:

```bash
bsot case new phishing-2025-01-15 --type phishing --severity medium
```

??? note "Output"
    ```
    📁 Case created: phishing-2025-01-15
       Location: ~/.bsot/cases/phishing-2025-01-15
       Status: active
    
       All BSOT command outputs will be saved to this case.
       Run `bsot case close` when investigation is complete.
    ```

---

## Step 2: Initial Email Analysis

Add the email to the case and perform initial analysis:

```bash
# Add email as evidence
bsot case add suspicious.eml

# Quick analysis
bsot phishing analyze suspicious.eml
```

??? example "Sample Output"
    ```
    📧 Phishing Analysis: suspicious.eml
    
    ┌─────────────────────────────────────────────────────────┐
    │ Risk Score: HIGH (8/10)                                 │
    ├─────────────────────────────────────────────────────────┤
    │ From:    "IT Support" <support@company-secure.net>      │
    │ To:      victim@yourcompany.com                         │
    │ Subject: Urgent: Verify your account immediately        │
    │ Date:    2025-01-15 09:15:32 UTC                        │
    └─────────────────────────────────────────────────────────┘
    
    ⚠️  Authentication Failures
        SPF:   FAIL
        DKIM:  FAIL
        DMARC: FAIL
    
    🔗 URLs Found (1)
        ⚠️  hxxps://company-secure[.]net/verify?token=abc123
            └─ Suspicious: Domain registered 3 days ago
    
    📎 Attachments (1)
        verify_account.html (12.4 KB)
        └─ ⚠️  HTML file with form elements
    
    📋 Extracted IOCs
        Domains: company-secure.net
        IPs:     185.234.72.45
    ```

**Key findings:**
- All email authentication failed (SPF, DKIM, DMARC)
- Suspicious domain registered recently
- HTML attachment with form (likely credential harvester)

---

## Step 3: Analyze Email Headers

Get detailed header information:

```bash
bsot phishing headers suspicious.eml
```

??? example "Sample Output"
    ```
    ── Authentication ────────────────────────────────────────
      SPF:   FAIL
      DKIM:  FAIL
      DMARC: FAIL
      Score: 0/100
    
    ── Sender Information ────────────────────────────────────
      Header From:   support@company-secure.net
      Envelope From: bounce@mail.evil-server.ru
      Reply-To:      support@company-secure.net
    
      [HIGH] From domain mismatch detected!
    
    ── Routing ───────────────────────────────────────────────
      Mail hops:     2
      Origin IP:     185.234.72.45 (evil-server.ru)
    ```

**Key findings:**
- Envelope-From domain is completely different (evil-server.ru)
- Origin IP is from Russia

---

## Step 4: Domain Intelligence

Check the suspicious domain:

```bash
bsot intel whois company-secure.net
```

??? example "Sample Output"
    ```
    ── WHOIS: company-secure.net ─────────────────────────────
    
    ── Registrar ─────────────────────────────────────────────
      Namecheap, Inc.
    
    ── Dates ─────────────────────────────────────────────────
      Created:  2025-01-12
      Age:      3 days
    
      [HIGH] Domain is only 3 days old - likely malicious
    
    ── Registrant ────────────────────────────────────────────
      🔒 WHOIS Privacy Protection: Enabled
    ```

The domain was registered just 3 days ago—classic phishing infrastructure.

---

## Step 5: IP Enrichment

Enrich the origin IP:

```bash
bsot intel enrich 185.234.72.45
```

??? example "Sample Output"
    ```
    🔍 Enriching ip: 185.234.72.45
    
      ▌ VERDICT: MALICIOUS
      ▌ CONFIDENCE: 92%
    
      📊 Sources: 3 malicious, 0 suspicious, 1 clean
      🌍 Country: Russia
      🏢 ASN: AS12345 Bulletproof Hosting Ltd
    
      🏷️  Tags: phishing, spam, botnet
    
    ── Source Details ────────────────────────────────────────
    
      VIRUSTOTAL: MALICIOUS
        Detection: 8/90
    
      ABUSEIPDB: MALICIOUS
        Abuse Score: 100%
        Reports: 847
    ```

Confirmed malicious IP with extensive abuse history.

---

## Step 6: Analyze Attachment

Check the HTML attachment:

```bash
# Extract strings from attachment
bsot file strings ./attachments/verify_account.html
```

??? example "Sample Output"
    ```
    ── Interesting Strings ───────────────────────────────────
      action="https://company-secure.net/steal.php"
      input type="password"
      input name="email"
      submit
    ```

The HTML file is a credential harvesting page that posts to `steal.php`.

---

## Step 7: Document Timeline

Add timeline events:

```bash
bsot case timeline "Phishing email received by user" --time "2025-01-15 09:15:00"
bsot case timeline "User forwarded email to security team" --time "2025-01-15 09:45:00"
bsot case timeline "Analysis confirmed credential harvesting attempt"
```

---

## Step 8: Add Investigation Notes

```bash
bsot case note "Confirmed phishing attack targeting company credentials"
bsot case note "Attacker infrastructure: company-secure.net (registered 3 days ago)"
bsot case note "No evidence user clicked link or submitted credentials"
bsot case note "Recommend blocking domain at email gateway and proxy"
```

---

## Step 9: Generate Report

Generate a report for stakeholders:

```bash
# Executive summary for management
bsot report generate --template executive -o executive_summary.md

# Technical report with IOCs
bsot report generate --template technical -o technical_report.md

# Export IOCs for blocklists
bsot report ioc --format csv -o iocs.csv
```

---

## Step 10: Close the Case

```bash
bsot case close
```

---

## Summary

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `bsot case new` | Create investigation case |
| 2 | `bsot phishing analyze` | Initial email analysis |
| 3 | `bsot phishing headers` | Detailed header inspection |
| 4 | `bsot intel whois` | Domain age and registration |
| 5 | `bsot intel enrich` | IP reputation check |
| 6 | `bsot file strings` | Attachment analysis |
| 7 | `bsot case timeline` | Document timeline |
| 8 | `bsot case note` | Add findings |
| 9 | `bsot report generate` | Create reports |
| 10 | `bsot case close` | Close investigation |

---

## Indicators of Compromise

| Type | Value | Description |
|------|-------|-------------|
| Domain | company-secure.net | Phishing domain |
| IP | 185.234.72.45 | Mail server origin |
| URL | hxxps://company-secure[.]net/verify | Credential harvester |
| Email | support@company-secure.net | Sender address |

---

## Recommendations

1. **Block the domain** at email gateway and web proxy
2. **Block the IP** at firewall
3. **User awareness** — remind users about phishing indicators
4. **Password reset** — if user submitted credentials
5. **Monitor** — watch for similar patterns

