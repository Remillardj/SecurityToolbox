# Data Module

Data encoding, decoding, and transformation utilities.

---

## Overview

The data module provides:

- Multiple encoding/decoding formats (Base64, URL, Hex, etc.)
- Timestamp parsing and conversion
- Hash calculation
- Regex testing
- Data formatting (JSON, XML)

---

## Commands

| Command | Description |
|---------|-------------|
| [`decode`](#bsot-data-decode) | Decode encoded data |
| [`encode`](#bsot-data-encode) | Encode data |
| [`timestamp`](#bsot-data-timestamp) | Parse and convert timestamps |
| [`hash`](#bsot-data-hash) | Calculate hash of data |
| [`regex`](#bsot-data-regex) | Test regex patterns |
| [`format`](#bsot-data-format) | Format/prettify data |

---

## `bsot data decode`

Decode data from various encoding formats.

### Usage

```bash
bsot data decode <encoding> <value> [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `encoding` | ✅ | Encoding type |
| `value` | - | Data to decode (or use stdin) |

### Supported Encodings

- `base64` — Base64 encoding
- `url` — URL encoding
- `hex` — Hexadecimal
- `html` — HTML entities
- `unicode-escape` — Unicode escape sequences
- `rot13` — ROT13 cipher
- `punycode` — Punycode (IDN domains)

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--file`, `-f` | PATH | Read from file |
| `--chain` | string | Chain decodings: "base64,url" |

### Examples

```bash
# Decode Base64
bsot data decode base64 "SGVsbG8gV29ybGQ="
# Output: Hello World

# Decode URL encoding
bsot data decode url "hello%20world"
# Output: hello world

# Decode hex
bsot data decode hex "48656c6c6f"
# Output: Hello

# From stdin
echo "SGVsbG8=" | bsot data decode base64 -

# Chain decodings (Base64 then URL)
bsot data decode base64 "..." --chain "base64,url"
```

---

## `bsot data encode`

Encode data into various formats.

### Usage

```bash
bsot data encode <encoding> <value> [OPTIONS]
```

### Examples

```bash
# Encode to Base64
bsot data encode base64 "Hello World"
# Output: SGVsbG8gV29ybGQ=

# URL encode
bsot data encode url "hello world"
# Output: hello%20world

# Hex encode
bsot data encode hex "Hello"
# Output: 48656c6c6f
```

---

## `bsot data timestamp`

Parse and convert timestamps between formats.

### Usage

```bash
bsot data timestamp [value] [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--to` | choice | `all` | Output: unix, unix-ms, iso, human, all |
| `--timezone`, `-tz` | string | `UTC` | Target timezone |
| `--json` | flag | `false` | JSON output |

### Auto-Detected Formats

- Unix epoch (seconds or milliseconds)
- ISO8601
- Common date formats (MM/DD/YYYY, etc.)

### Examples

```bash
# Current time
bsot data timestamp now

# Parse Unix timestamp
bsot data timestamp 1703462400

# Parse ISO8601
bsot data timestamp "2024-12-25T00:00:00Z"

# Specific output format
bsot data timestamp 1703462400 --to iso

# With timezone
bsot data timestamp 1703462400 --timezone "America/New_York"
```

??? example "Sample Output"

    ```
    Timestamp Conversion:
      Original:  1703462400
      Unix:      1703462400
      Unix (ms): 1703462400000
      ISO8601:   2024-12-25T00:00:00+00:00
      Human:     Wednesday, December 25, 2024, 00:00:00 UTC
      Relative:  2 weeks ago
      Timezone:  UTC
    ```

---

## `bsot data hash`

Calculate hash of a string or file.

### Usage

```bash
bsot data hash <algorithm> [value] [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `algorithm` | ✅ | md5, sha1, sha256, sha512 |
| `value` | - | String to hash (or use stdin/file) |

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--file`, `-f` | PATH | Hash file instead of string |

### Examples

```bash
# Hash a string
bsot data hash sha256 "test string"

# Hash a file
bsot data hash md5 -f myfile.txt

# From stdin
echo "test" | bsot data hash sha256 -
```

---

## `bsot data regex`

Test regex patterns against data.

### Usage

```bash
bsot data regex <pattern> [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--file`, `-f` | PATH | Test against file |
| `--test`, `-t` | string | Test against string |
| `--highlight` | flag | Highlight matches |

### Examples

```bash
# Test against string
bsot data regex "\\d+" --test "abc123def456"

# Test against file
bsot data regex "error|warning" -f logfile.txt

# With highlighting
bsot data regex "error" -f log.txt --highlight
```

---

## `bsot data format`

Format/prettify data (JSON, XML, HTML).

### Usage

```bash
bsot data format <type> [value] [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `type` | ✅ | json, xml, html |
| `value` | - | Data to format (or use stdin/file) |

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--file`, `-f` | PATH | Input file |
| `--minify` | flag | Minify instead of prettify |
| `--sort-keys` | flag | Sort object keys (JSON) |

### Examples

```bash
# Prettify JSON
bsot data format json '{"a":1,"b":2}'

# Minify JSON
bsot data format json -f data.json --minify

# Format from stdin
echo '{"a":1}' | bsot data format json

# Sort keys
bsot data format json '{"b":2,"a":1}' --sort-keys
```

---

## Related Commands

- [`bsot malware deobfuscate`](malware.md#bsot-malware-deobfuscate) — Decode malware obfuscation

