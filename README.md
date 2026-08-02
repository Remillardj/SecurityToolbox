# BSOT — Blue Security Ops Toolkit

A command-line toolkit for blue team security operations. Analyze phishing
emails, enrich IOCs, triage malware, investigate logs, audit hosts, and build
case reports — all from the terminal.

Every command supports `--json`, so results pipe cleanly into `jq`, a SIEM, or
whatever comes next in your pipeline.

## Installation

```bash
git clone git@github.com:Remillardj/SecurityToolbox.git
cd SecurityToolbox
pip install -e .
bsot --help
```

Optional features live behind extras:

```bash
pip install -e ".[full]"      # WHOIS, EXIF, PDF, .msg parsing, rich output
pip install -e ".[malware]"   # PE analysis, YARA, fuzzy hashing
pip install -e ".[report]"    # AI analysis and report generation
```

Requires Python 3.9 or newer.

## Configuration

API keys come from environment variables or `~/.bsot/config.json`:

```bash
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
export ANTHROPIC_API_KEY=your_key   # for AI-assisted analysis
```

To see what is configured and what each key unlocks:

```bash
bsot config check          # what is set
bsot config check --live   # validate each key against the provider
```

Named profiles let you keep separate key sets:

```bash
bsot config create-profile work
bsot --profile work intel enrich 1.2.3.4
```

## Shell completion

```bash
bsot completion zsh > ~/.bsot-completion.zsh
echo 'source ~/.bsot-completion.zsh' >> ~/.zshrc
```

`bash` and `fish` are also supported.

## Commands

### Phishing (`bsot phishing`)
| Command | Purpose |
|---|---|
| `analyze` | Full email analysis |
| `headers` | Parse and score email headers |
| `extract-iocs` | Pull IOCs out of an email |
| `reputation` | Check extracted IOCs against reputation sources |
| `ai-analyze` | AI-assisted assessment |

### Threat intelligence (`bsot intel`)
| Command | Purpose |
|---|---|
| `enrich` | Enrich an IOC across configured sources |
| `bulk` | Enrich many IOCs, rate-limited per source |
| `mitre` | Look up ATT&CK techniques by ID, keyword, or tactic |
| `cve` | Search CVEs by keyword or ID |
| `whois` | Domain WHOIS |
| `geoip` | IP geolocation |
| `defang` / `refang` | Make IOCs safe (or unsafe) to paste |

### Logs (`bsot logs`)
| Command | Purpose |
|---|---|
| `analyze` | Detect attack patterns, tagged with ATT&CK techniques |
| `timeline` | Build an investigative timeline |
| `parse` | Parse and normalize syslog, JSON, CLF, CEF |
| `stats` | Summary statistics |
| `ai-analyze` | AI-assisted log review |

### Files (`bsot file`)
| Command | Purpose |
|---|---|
| `hash` | Calculate and verify hashes |
| `identify` | Identify type by magic bytes, flag extension mismatches |
| `strings` | Extract strings, highlighting interesting ones |
| `entropy` | Entropy analysis for packing and encryption |
| `metadata` | EXIF, PDF, and Office metadata |
| `cred-scan` | Find hardcoded credentials |
| `permissions` | Find world-writable files and unsafe directories |
| `suid-finder` | Find SUID/SGID binaries |
| `baseline` / `diff` | Record a hash manifest and detect drift |

### Network (`bsot network`)
| Command | Purpose |
|---|---|
| `ssl-check` | Certificate and TLS configuration analysis |
| `dns` | DNS records plus SPF/DKIM/DMARC |
| `headers` | HTTP security header audit |
| `ports` | Port scan |
| `ct-subdomains` | Passive subdomain enumeration via Certificate Transparency |

### Malware (`bsot malware`)
| Command | Purpose |
|---|---|
| `pe` | PE structure analysis |
| `yara` | Scan with YARA rules |
| `strings` | String analysis |
| `deobfuscate` | Unwrap obfuscated scripts |
| `ioc` | Extract IOCs from a sample |
| `compare` | Fuzzy-hash comparison |
| `submit` | Submit to a sandbox |

### System (`bsot system`)
| Command | Purpose |
|---|---|
| `processes` | List processes and flag suspicious ones (`--vt` for VirusTotal) |
| `connections` | Active network connections |
| `persistence` | Enumerate launch agents, systemd units, and cron |

### Data (`bsot data`)
| Command | Purpose |
|---|---|
| `magic` | Auto-detect and recursively decode layered encodings |
| `decode` / `encode` | base64, hex, URL, HTML, unicode, ROT13, punycode |
| `hash` | Hash a string |
| `timestamp` | Convert between timestamp formats |
| `regex` | Test a pattern against sample data |
| `format` | Pretty-print JSON and XML |

### Authentication (`bsot auth`)
| Command | Purpose |
|---|---|
| `password-analyze` | Strength analysis with breach lookup |
| `jwt-decode` | Decode and audit a JWT |
| `ssh-audit` | Audit sshd config against OpenSSH defaults |

### Incident response (`bsot ir`)
| Command | Purpose |
|---|---|
| `collect` | Collect host artifacts |
| `hash-tree` | Hash a directory tree for evidence |
| `contain` / `block` / `unblock` | Cloudflare containment actions |
| `bulk-block` | Block many indicators at once |
| `list` | List active blocks |

### Cases and reports (`bsot case`, `bsot report`)
| Command | Purpose |
|---|---|
| `new` / `open` / `close` | Case lifecycle |
| `add` / `note` / `ioc` | Attach evidence |
| `timeline` / `status` | Review a case |
| `generate` | Produce a report |
| `package` | Package a case for handoff |

### OSINT (`bsot osint`)
| Command | Purpose |
|---|---|
| `domain` | Domain profile: WHOIS, DNS, email security, SSL, subdomains |

## Examples

```bash
# Triage a suspicious email
bsot phishing analyze suspicious.eml

# Enrich an indicator and keep the JSON
bsot intel enrich 1.2.3.4 --json > enrichment.json

# What does this ATT&CK technique mean?
bsot intel mitre T1110.001

# Unwrap a layered payload
bsot data magic "H4sIAAAAAAAC/8tIzcnJVyjPL8pJAQCFEUoNCwAAAA=="

# Audit a host
bsot file permissions /var/www
bsot file suid-finder /usr/bin
bsot auth ssh-audit /etc/ssh/sshd_config
bsot system persistence

# Watch a directory for tampering
bsot file baseline /etc -o etc-baseline.json
bsot file diff etc-baseline.json

# Passive recon
bsot network ct-subdomains example.com --resolve
bsot osint domain example.com --deep
```

## Exit codes

Commands are scriptable: `0` means clean, `1` means findings were reported,
and `2` means the command could not run (bad input, missing dependency,
unreachable service).

```bash
bsot file cred-scan . && echo "no secrets found"
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check bsot/ tests/
```

## License

Copyright (c) 2025 Jaryd Remillard. All rights reserved.

This software is licensed for personal, non-commercial use only. You may use
and modify the software for private purposes, but distribution is prohibited.

Key restrictions:

✅ Personal use allowed

✅ Modifications for personal use allowed

❌ No distribution of original or modified versions

❌ No commercial use

Commercial licensing: For commercial use or distribution rights, contact
jaryd.remillard@gmail.com

See the LICENSE file for full terms.

## Issues

Bug reports and feature requests are welcome via GitHub issues. Because the
license above does not grant redistribution rights, please get in touch at
jaryd.remillard@gmail.com before submitting code.

## Links

- **Website**: [bluesecurityops.com](https://bluesecurityops.com)
- **GitHub**: [github.com/Remillardj/SecurityToolbox](https://github.com/Remillardj/SecurityToolbox)
