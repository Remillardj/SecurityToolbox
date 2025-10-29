# BSOT Quick Usage Guide

## Installation

```bash
# Install in development mode
pip install -e .

# Or run directly
python3 bsot.py --help
```

## Command Categories

### 1. File Security (`bsot file`)

**Check file permissions:**
```bash
python3 bsot.py file permissions /var/www
python3 bsot.py file permissions . --verbose
```

**Find SUID/SGID binaries:**
```bash
python3 bsot.py file suid-finder /usr/bin
python3 bsot.py file suid-finder / --verbose
```

**Scan for hardcoded credentials:**
```bash
python3 bsot.py file cred-scan /path/to/project
python3 bsot.py file cred-scan . --extensions "py,js,env,yaml"
python3 bsot.py file cred-scan ./src --context 3
```

**Calculate file hashes:**
```bash
python3 bsot.py file hash-check myfile.zip
python3 bsot.py file hash-check download.iso --algorithm sha512 --compare abc123...
```

### 2. Network Security (`bsot network`)

**Check SSL/TLS certificates:**
```bash
python3 bsot.py network ssl-check google.com
python3 bsot.py network ssl-check example.com --port 8443
python3 bsot.py network ssl-check mysite.com --check-expiry
python3 bsot.py network ssl-check github.com --verbose --json
```

**Scan ports:**
```bash
python3 bsot.py network port-scan 192.168.1.1
python3 bsot.py network port-scan example.com --ports 80,443,8080
python3 bsot.py network port-scan 10.0.0.1 --ports 1-1000 --timeout 0.5
```

**Check web security headers:**
```bash
python3 bsot.py network web-headers https://example.com
python3 bsot.py network web-headers https://github.com --verbose
python3 bsot.py network web-headers https://mysite.com --json
```

**DNS security lookup:**
```bash
python3 bsot.py network dns-lookup example.com
python3 bsot.py network dns-lookup google.com --type MX
python3 bsot.py network dns-lookup example.com --verbose --json
```

### 3. Data Analysis (`bsot data`)

**Decode URL-encoded strings:**
```bash
python3 bsot.py data url-decode "Hello%20World%21"
python3 bsot.py data url-decode "name%3Dvalue%26foo%3Dbar" --recursive
python3 bsot.py data url-decode "test+string" --plus
```

**Decode base64:**
```bash
python3 bsot.py data base64-decode "SGVsbG8gV29ybGQ="
python3 bsot.py data base64-decode --file encoded.txt
python3 bsot.py data base64-decode "U0dWc2JHOGdWMjl5YkdRPQ==" --recursive
```

**Decode hexadecimal:**
```bash
python3 bsot.py data hex-decode "48656c6c6f20576f726c64"
python3 bsot.py data hex-decode "0x480x650x6c0x6c0x6f" --prefix
python3 bsot.py data hex-decode --file hex_data.txt
```

**Analyze email headers:**
```bash
python3 bsot.py data email-header suspicious_email.txt
python3 bsot.py data email-header headers.txt --verbose
python3 bsot.py data email-header phishing.txt --json
```

### 4. Authentication Security (`bsot auth`)

**Analyze password strength:**
```bash
python3 bsot.py auth password-analyze "MyP@ssw0rd123"
python3 bsot.py auth password-analyze --file passwords.txt
python3 bsot.py auth password-analyze "test123" --verbose
```

**Decode JWT tokens:**
```bash
python3 bsot.py auth jwt-decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
python3 bsot.py auth jwt-decode <token> --verbose
python3 bsot.py auth jwt-decode <token> --verify "secret-key"
```

**Audit SSH configuration:**
```bash
python3 bsot.py auth ssh-audit
python3 bsot.py auth ssh-audit /etc/ssh/sshd_config
python3 bsot.py auth ssh-audit ~/.ssh/config --verbose
```

### 5. System Monitoring (`bsot system`)

**Check for suspicious processes:**
```bash
python3 bsot.py system process-check
python3 bsot.py system process-check --verbose
python3 bsot.py system process-check --vt-api-key YOUR_API_KEY
```

### 6. Log Analysis (`bsot logs`)

**Analyze log files:**
```bash
python3 bsot.py logs analyze /var/log/auth.log
python3 bsot.py logs analyze access.log --focus ip
python3 bsot.py logs analyze auth.log --focus brute_force
python3 bsot.py logs analyze app.log --query "What is the compromised account?"
python3 bsot.py logs analyze server.log --patterns custom_patterns.json --output json
```

## Advanced Usage

### Custom Patterns for Log Analysis

Create a JSON file with custom regex patterns:

```json
{
  "api_calls": "API call to /v1/.*",
  "credit_cards": "\\d{4}-\\d{4}-\\d{4}-\\d{4}",
  "custom_error": "CUSTOM_ERROR:\\s+.*"
}
```

Then use it:
```bash
python3 bsot.py logs analyze app.log --patterns custom_patterns.json
```

### Environment Variables

- `VT_API_KEY` - VirusTotal API key for malware scanning

```bash
export VT_API_KEY="your-api-key-here"
python3 bsot.py system process-check
```

## Tips

1. Use `--help` on any command to see all options
2. Most commands support `--verbose` for detailed output
3. Many commands support `--json` for machine-readable output
4. Combine with standard Unix tools for powerful workflows:
   ```bash
   python3 bsot.py network port-scan 192.168.1.1 | grep OPEN
   python3 bsot.py file cred-scan . --json | jq '.findings'
   ```
