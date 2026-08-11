# OSINT Module

Open Source Intelligence (OSINT) gathering tools.

!!! warning "Coming Soon"
    This module is scaffolded for future development. Commands are defined but not yet fully implemented.

---

## Overview

The OSINT module will provide:

- Domain reconnaissance (WHOIS, DNS, subdomains)
- Email investigation and breach lookup
- Username enumeration across platforms
- Person search across public sources
- Image EXIF extraction and reverse search
- Company intelligence gathering
- Phone number lookup
- Google dorking helpers
- Paste site searching
- Web archive lookups

---

## Planned Commands

| Command | Description | Status |
|---------|-------------|--------|
| [`domain`](#bsot-osint-domain) | Domain reconnaissance | 🚧 Coming Soon |
| [`email`](#bsot-osint-email) | Email investigation | 🚧 Coming Soon |
| [`username`](#bsot-osint-username) | Username enumeration | 🚧 Coming Soon |
| [`person`](#bsot-osint-person) | Person search | 🚧 Coming Soon |
| [`image`](#bsot-osint-image) | Image analysis | 🚧 Coming Soon |
| [`metadata`](#bsot-osint-metadata) | File metadata extraction | 🚧 Coming Soon |
| [`company`](#bsot-osint-company) | Company intelligence | 🚧 Coming Soon |
| [`phone`](#bsot-osint-phone) | Phone number lookup | 🚧 Coming Soon |
| [`dork`](#bsot-osint-dork) | Google dorking | 🚧 Coming Soon |
| [`pastebin`](#bsot-osint-pastebin) | Paste site search | 🚧 Coming Soon |
| [`archive`](#bsot-osint-archive) | Web archive lookup | 🚧 Coming Soon |

---

## `bsot osint domain`

Comprehensive domain reconnaissance.

### Planned Features

- WHOIS registration data
- DNS records (A, MX, TXT, NS, etc.)
- Subdomain enumeration
- Technology stack detection
- SSL certificate details
- Historical WHOIS changes
- Related domains discovery

### Usage (Preview)

```bash
bsot osint domain example.com
bsot osint domain example.com --deep
```

---

## `bsot osint email`

Email address investigation.

### Planned Features

- Email format validation
- Breach exposure lookup (HIBP)
- Gravatar/profile picture discovery
- Social media account detection
- Domain MX/SPF reputation

### Usage (Preview)

```bash
bsot osint email user@example.com
bsot osint email user@example.com --breaches
```

---

## `bsot osint username`

Check username availability across platforms.

### Planned Features

- 100+ platform checks
- Parallel checking for speed
- Profile URL extraction
- Account age/activity detection

### Usage (Preview)

```bash
bsot osint username johndoe
bsot osint username johndoe --platforms github,twitter,reddit
```

---

## `bsot osint person`

Aggregate person search across public sources.

### Planned Features

- Social media profile discovery
- Professional network search
- News/media mentions
- Public records lookup
- Relationship mapping

### Usage (Preview)

```bash
bsot osint person "John Doe"
bsot osint person "John Doe" --location "New York"
```

---

## `bsot osint image`

Image analysis and EXIF extraction.

### Planned Features

- Full EXIF metadata extraction
- GPS coordinate extraction
- Reverse image search
- Face detection
- Image hash generation

### Usage (Preview)

```bash
bsot osint image photo.jpg
bsot osint image photo.jpg --reverse-search
```

---

## `bsot osint company`

Company/organization intelligence gathering.

### Planned Features

- Associated domains discovery
- Tech stack from job postings
- Key personnel identification
- Social media presence
- Subsidiary relationships
- IP ranges (ASN lookup)

### Usage (Preview)

```bash
bsot osint company "Acme Corporation"
bsot osint company "Acme Corp" --domain acme.com
```

---

## `bsot osint dork`

Google dorking query generator.

### Planned Features

- Dork template library
- Exposed files (PDF, DOC, configs)
- Login/admin pages
- Sensitive directories
- Error messages

### Usage (Preview)

```bash
bsot osint dork example.com
bsot osint dork example.com --category files
```

---

## `bsot osint archive`

Fetch historical snapshots from web archives.

### Planned Features

- Wayback Machine integration
- Snapshot listing
- Specific date fetch
- Version comparison
- Deleted page discovery

### Usage (Preview)

```bash
bsot osint archive https://example.com
bsot osint archive https://example.com --list
bsot osint archive https://example.com --date 2020-01-01
```

---

## Current Workarounds

While the OSINT module is under development, you can use these existing BSOT features:

| Task | Current Alternative |
|------|---------------------|
| Domain WHOIS | `bsot intel whois example.com` |
| IP geolocation | `bsot intel geoip 1.2.3.4` |
| File metadata | `bsot file metadata image.jpg` |
| Email headers | `bsot phishing headers email.eml` |

---

## Contributing

Want to help implement OSINT features? Check the [GitHub repository](https://github.com/Remillardj/SecurityToolbox) for contribution guidelines.

