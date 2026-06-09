# File Module

File analysis and forensics tools including hashing, identification, entropy analysis, and secret scanning.

---

## Overview

The file module provides:

- Multi-algorithm file hashing (MD5, SHA1, SHA256, SHA512)
- File type identification via magic bytes
- Entropy analysis for detecting packing/encryption
- String extraction from binaries
- Metadata extraction from documents and images
- Secret/credential scanning

---

## Commands

| Command | Description |
|---------|-------------|
| [`hash`](#bsot-file-hash) | Calculate file hashes |
| [`identify`](#bsot-file-identify) | Identify file type by magic bytes |
| [`strings`](#bsot-file-strings) | Extract printable strings |
| [`entropy`](#bsot-file-entropy) | Analyze file entropy |
| [`metadata`](#bsot-file-metadata) | Extract file metadata |
| [`cred-scan`](#bsot-file-cred-scan) | Scan for hardcoded secrets |

---

## `bsot file hash`

Calculate file hashes using various algorithms.

### Usage

```bash
bsot file hash <files...> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--algo`, `-a` | string | `sha256` | Algorithms: md5, sha1, sha256, sha512, all |
| `--all` | flag | `false` | Calculate all algorithms |
| `--verify`, `-v` | string | - | Verify against expected hash |
| `--recursive`, `-r` | flag | `false` | Hash directories recursively |
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Basic SHA256 hash
bsot file hash malware.exe

# Multiple algorithms
bsot file hash file.txt --algo md5,sha256

# All algorithms
bsot file hash file.txt --all

# Verify a hash
bsot file hash file.txt --verify abc123def456...

# Hash a directory recursively
bsot file hash ./evidence -r

# JSON output
bsot file hash *.exe --json
```

??? example "Sample Output"

    ```
    malware.exe
      Size: 245,760 bytes
      MD5: d41d8cd98f00b204e9800998ecf8427e
      SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
      SHA256: e3b0c44298fc1c149afbf4c8996fb924...
    ```

---

## `bsot file identify`

Identify file type by examining magic bytes (file signature).

### Usage

```bash
bsot file identify <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Identify a file
bsot file identify suspicious.pdf

# Check for extension mismatch
bsot file identify invoice.pdf.exe
```

??? example "Sample Output"

    ```
    File: invoice.pdf
      Size: 47,352 bytes
      MIME Type: application/pdf
      Description: PDF document
      Magic Bytes: 25 50 44 46
      Expected Extensions: .pdf
    
    File: invoice.pdf.exe
      Size: 245,760 bytes
      MIME Type: application/x-executable
      Description: PE32 executable (GUI)
      Magic Bytes: 4D 5A
      Expected Extensions: .exe, .dll
    
      [HIGH] Extension Mismatch Detected!
        File has .pdf.exe extension but is a Windows executable
    ```

---

## `bsot file strings`

Extract printable strings from binary files.

### Usage

```bash
bsot file strings <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--min-length`, `-m` | int | `4` | Minimum string length |
| `--encoding`, `-e` | choice | `both` | `ascii`, `unicode`, or `both` |
| `--interesting`, `-i` | flag | `false` | Only show interesting strings |
| `--max-strings` | int | `1000` | Maximum strings to extract |
| `--json` | flag | `false` | JSON output |

### Examples

```bash
# Basic string extraction
bsot file strings malware.exe

# Longer strings only
bsot file strings malware.exe --min-length 8

# Only interesting strings (URLs, IPs, paths)
bsot file strings malware.exe --interesting

# JSON output
bsot file strings malware.exe --json
```

---

## `bsot file entropy`

Calculate file entropy to detect packing or encryption.

### Usage

```bash
bsot file entropy <file> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--block-size`, `-b` | int | `256` | Block size for analysis |
| `--blocks` | flag | `false` | Show per-block analysis |
| `--visualize`, `-v` | flag | `false` | Show ASCII visualization |
| `--json` | flag | `false` | JSON output |

### Entropy Scale

- **0-5**: Low entropy (text, structured data)
- **5-7**: Normal entropy (typical binaries)
- **7-7.5**: Medium-high (compressed data)
- **7.5-8**: High entropy (encrypted/random data)

### Examples

```bash
# Basic entropy analysis
bsot file entropy suspicious.exe

# With block analysis
bsot file entropy packed.bin --blocks

# With visualization
bsot file entropy packed.bin --visualize
```

??? example "Sample Output"

    ```
    Entropy Analysis: suspicious.exe
      File size: 245,760 bytes
      Entropy: 7.82/8.0
      Verdict: HIGH
    
      ⚠️  High entropy detected - file may be encrypted, packed, or obfuscated
    
      Block Analysis (block size: 256):
        Min entropy: 6.21
        Max entropy: 7.98
        Avg entropy: 7.65
        High entropy blocks: 847/960
    ```

---

## `bsot file metadata`

Extract metadata from files (images, PDFs, Office documents).

### Usage

```bash
bsot file metadata <file> [OPTIONS]
```

### Examples

```bash
# Image metadata (EXIF)
bsot file metadata photo.jpg

# PDF metadata
bsot file metadata document.pdf

# JSON output
bsot file metadata image.jpg --json
```

---

## `bsot file cred-scan`

Scan for hardcoded credentials and secrets in source code.

### Usage

```bash
bsot file cred-scan <path> [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--recursive`, `-r` | flag | `true` | Scan recursively |
| `--no-recursive` | flag | `false` | Disable recursive scanning |
| `--include-low`, `-l` | flag | `false` | Include low-confidence findings |
| `--json` | flag | `false` | JSON output |
| `--quiet`, `-q` | flag | `false` | Only output on findings (for CI) |

### Detected Secrets

- AWS Access Keys
- API Keys (generic patterns)
- Private Keys (RSA, SSH, PGP)
- Passwords in config files
- OAuth tokens
- JWT tokens
- Database connection strings
- And more...

### Examples

```bash
# Scan current directory
bsot file cred-scan .

# Scan specific directory
bsot file cred-scan src/

# Include low-confidence findings
bsot file cred-scan . --include-low

# CI/CD usage
bsot file cred-scan . --quiet --json > secrets.json || exit 1
```

??? example "Sample Output"

    ```
    ══════════════════════════════════════════════════════════
      Secret Scan Results
    ══════════════════════════════════════════════════════════
      Path: ./src
      Files scanned: 47
      Files with secrets: 2
      Total findings: 3
    
    ── Findings ──────────────────────────────────────────────
    
      src/config.py
        Line 15: [HIGH] AWS Access Key
          Match: AKIAIOSFODNN7EXAMPLE
    
        Line 16: [HIGH] AWS Secret Key
          Match: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    
      src/api/client.py
        Line 42: [MEDIUM] Generic API Key
          Match: api_key = "sk_live_..."
    
      ⚠️  3 secret(s) detected!
         Review and remove before committing.
    ```

### Exit Codes

- `0` — No secrets found
- `1` — Secrets detected
- `2` — Error

---

## Related Commands

- [`bsot malware strings`](malware.md#bsot-malware-strings) — Advanced string analysis
- [`bsot malware pe`](malware.md#bsot-malware-pe) — PE file analysis

