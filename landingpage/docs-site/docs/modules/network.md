# Network Module

Network security analysis tools including SSL/TLS checking, security headers, DNS, and port scanning.

---

## Overview

The network module provides:

- SSL/TLS certificate analysis and grading
- HTTP security header auditing
- DNS security analysis (SPF, DKIM, DMARC, DNSSEC)
- Basic port scanning

---

## Commands

| Command | Description |
|---------|-------------|
| [`ssl-check`](#bsot-network-ssl-check) | SSL/TLS certificate analysis |
| [`headers`](#bsot-network-headers) | HTTP security header audit |
| [`dns`](#bsot-network-dns) | DNS security analysis |
| [`ports`](#bsot-network-ports) | Port scanning |

---

## `bsot network ssl-check`

Comprehensive SSL/TLS certificate and configuration analysis.

### Usage

```bash
bsot network ssl-check <host> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--port`, `-p` | int | `443` | Port number |
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Check SSL certificate
bsot network ssl-check google.com

# Custom port
bsot network ssl-check example.com:8443
bsot network ssl-check example.com --port 8443

# JSON output
bsot network ssl-check example.com --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      SSL/TLS Check: example.com:443
    ══════════════════════════════════════════════════════════
    
      Grade: A
    
    ── Certificate ───────────────────────────────────────────
      Subject: example.com
      Issuer: Let's Encrypt Authority X3
      Valid From: 2025-01-01
      Valid Until: 2025-04-01
      ✓ Expires in 76 days
    
      Alternative Names: example.com, www.example.com
    
    ── Protocol & Cipher ─────────────────────────────────────
      Protocol: TLSv1.3
      Cipher: TLS_AES_256_GCM_SHA384
      Key Size: 256 bits
    ```

---

## `bsot network headers`

Audit HTTP security headers.

### Usage

```bash
bsot network headers <url> [OPTIONS]
```

### Examples

```bash
# Check security headers
bsot network headers https://example.com

# Without https prefix
bsot network headers example.com

# JSON output
bsot network headers example.com --json
```

### Checked Headers

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

---

## `bsot network dns`

DNS security analysis including email authentication (SPF, DKIM, DMARC).

### Usage

```bash
bsot network dns <domain> [OPTIONS]
```

### Examples

```bash
# Check DNS security
bsot network dns example.com

# JSON output
bsot network dns google.com --json
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      DNS Security: example.com
    ══════════════════════════════════════════════════════════
    
      Email Security Grade: A
    
    ── DNS Records ───────────────────────────────────────────
      A: 93.184.216.34
      MX: 10 mail.example.com
      NS: ns1.example.com, ns2.example.com
    
    ── Email Authentication ──────────────────────────────────
      ✓ SPF: v=spf1 include:_spf.google.com ~all
      ✓ DMARC: v=DMARC1; p=reject; rua=mailto:...
      ✓ DKIM: Found (selector: google)
    
    ── Security ──────────────────────────────────────────────
      ✓ DNSSEC: Enabled
      ✓ CAA: letsencrypt.org
    ```

---

## `bsot network ports`

Scan for open ports on a host.

### Usage

```bash
bsot network ports <host> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--ports`, `-p` | string | `common` | Ports: "22,80,443", "1-1000", or "common" |
| `--timeout`, `-t` | int | `1000` | Timeout per port in ms |
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Scan common ports
bsot network ports example.com

# Scan specific ports
bsot network ports 192.168.1.1 --ports 22,80,443,8080

# Scan port range
bsot network ports server.local --ports 1-1000

# JSON output
bsot network ports example.com --json
```

---

## Related Commands

- [`bsot intel whois`](intel.md#bsot-intel-whois) — Domain WHOIS lookup
- [`bsot intel geoip`](intel.md#bsot-intel-geoip) — IP geolocation

