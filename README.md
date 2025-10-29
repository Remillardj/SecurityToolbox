# BSOT - Blue Security Ops Toolkit

A comprehensive command-line security toolkit for system administrators, security professionals, and DevOps engineers. BSOT provides practical, easy-to-use tools for file analysis, network scanning, data decoding, authentication auditing, system monitoring, and log analysis.

## Features

### File Security (`bsot file`)
- **permissions** - Scan for files with overly permissive permissions
- **suid-finder** - Find SUID/SGID binaries (privilege escalation vectors)
- **cred-scan** - Detect hardcoded credentials and secrets in files
- **hash-check** - Calculate and verify file hashes

### Network Security (`bsot network`)
- **ssl-check** - Verify SSL/TLS certificates and check security configuration
- **port-scan** - Scan for open ports on target hosts
- **web-headers** - Audit HTTP security headers
- **dns-lookup** - Perform DNS security lookups (SPF, DMARC, etc.)

### Data Analysis (`bsot data`)
- **url-decode** - Decode URL-encoded strings
- **base64-decode** - Decode base64-encoded data
- **hex-decode** - Decode hexadecimal strings
- **email-header** - Analyze email headers for security issues

### Authentication (`bsot auth`)
- **password-analyze** - Analyze password strength and security
- **jwt-decode** - Decode and analyze JWT tokens
- **ssh-audit** - Audit SSH configuration for security issues

### System Monitoring (`bsot system`)
- **process-check** - Detect suspicious processes (with optional VirusTotal integration)

### Log Analysis (`bsot logs`)
- **analyze** - Comprehensive log analysis with attack detection, brute force identification, and pattern matching

## Installation

```bash
# Install from source
git clone <repository-url>
cd SecurityToolbox
pip install -e .

# Or install requirements manually
pip install -r requirements.txt
```

## Quick Start Examples

```bash
# File security
bsot file permissions /var/www
bsot file suid-finder /usr/bin
bsot file cred-scan ./my-project --extensions "py,js,env"
bsot file hash-check download.iso --compare abc123...

# Network security
bsot network ssl-check google.com
bsot network port-scan 192.168.1.1 --ports 1-1024
bsot network web-headers https://example.com
bsot network dns-lookup example.com

# Data analysis
bsot data url-decode "Hello%20World%21"
bsot data base64-decode "SGVsbG8gV29ybGQ="
bsot data hex-decode "48656c6c6f"
bsot data email-header suspicious_email.txt

# Authentication
bsot auth password-analyze "MyP@ssw0rd123"
bsot auth jwt-decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
bsot auth ssh-audit /etc/ssh/sshd_config

# System monitoring
bsot system process-check --vt-api-key YOUR_KEY

# Log analysis
bsot logs analyze /var/log/auth.log
bsot logs analyze access.log --focus brute_force
bsot logs analyze app.log --output json
```

## Environment Variables

- `VT_API_KEY` - VirusTotal API key for malware scanning (optional)

## Command Structure

All commands follow this pattern:
```
bsot <category> <command> [arguments] [options]
```

Categories:
- `file` - File security analysis
- `network` - Network security scanning
- `data` - Data encoding/decoding
- `auth` - Authentication security
- `system` - System monitoring
- `logs` - Log analysis

## Help

Get help for any command:
```bash
bsot --help
bsot file --help
bsot network ssl-check --help
```

## Requirements

- Python 3.7+
- click>=8.0.0
- requests>=2.25.0
- dnspython>=2.1.0

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.
