# Auth Module

Authentication security tools including password analysis and JWT decoding.

---

## Overview

The auth module provides:

- Password strength analysis
- Breach database checking (Have I Been Pwned)
- JWT token decoding and validation
- Security vulnerability detection in tokens

---

## Commands

| Command | Description |
|---------|-------------|
| [`password-analyze`](#bsot-auth-password-analyze) | Analyze password strength |
| [`jwt-decode`](#bsot-auth-jwt-decode) | Decode and analyze JWT tokens |

---

## `bsot auth password-analyze`

Analyze password strength and check for breaches.

### Usage

```bash
bsot auth password-analyze [password] [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--check-breach` | flag | `false` | Check against Have I Been Pwned |
| `--json` | flag | `false` | JSON output |

### Analysis Criteria

- Length and character diversity
- Entropy calculation
- Common pattern detection
- Dictionary word detection
- Keyboard pattern detection

### Examples

```bash
# Analyze password (prompted securely)
bsot auth password-analyze

# Analyze specific password
bsot auth password-analyze "MyP@ssw0rd!"

# Check against breach database
bsot auth password-analyze "password123" --check-breach
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Password Analysis
    ══════════════════════════════════════════════════════════
    
      Strength: WEAK
      Score: 35/100
    
    ── Details ───────────────────────────────────────────────
      Length: 11 characters
      Entropy: 32.1 bits
      Character types: lowercase, digits
    
    ── Patterns Detected ─────────────────────────────────────
      ⚠️  Common substitution pattern (a -> @, o -> 0)
      ⚠️  Based on dictionary word: "password"
      ⚠️  Ends with common number sequence
    
    ── Breach Check ──────────────────────────────────────────
      ✗ Found in 23,547 data breaches!
    
    ── Recommendations ───────────────────────────────────────
      • Use a passphrase instead of a modified word
      • Add more character types
      • Increase length to at least 16 characters
      • Avoid common patterns
    ```

---

## `bsot auth jwt-decode`

Decode and analyze JWT tokens.

### Usage

```bash
bsot auth jwt-decode [token] [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--verify` | string | - | Key for signature verification |
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Decode a token
bsot auth jwt-decode "eyJhbGciOiJIUzI1NiIs..."

# From stdin
echo "eyJ..." | bsot auth jwt-decode

# Verify signature
bsot auth jwt-decode "eyJ..." --verify "my-secret-key"
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      JWT Analysis
    ══════════════════════════════════════════════════════════
    
    ── Header ────────────────────────────────────────────────
      Algorithm: HS256
      Type: JWT
    
    ── Payload ───────────────────────────────────────────────
      sub: 1234567890
      name: John Doe
      iat: 1516239022 (2018-01-18T01:30:22+00:00)
      exp: 1516325422 (2018-01-19T01:30:22+00:00)
      admin: true
    
    ── Expiration ────────────────────────────────────────────
      ✗ EXPIRED
      Expired 7 years ago
    
    ── Security ──────────────────────────────────────────────
      ! No expiration set in original claim
      ✗ Token uses weak algorithm (HS256)
    ```

### Security Checks

- Expiration validation
- Algorithm strength
- None algorithm vulnerability
- Sensitive data in payload

---

## Related Commands

- [`bsot data decode`](data.md#bsot-data-decode) — Decode Base64 data

