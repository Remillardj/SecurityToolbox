# BSOT - Blue Security Ops Toolkit

## Project Complete ✅

All existing security tools have been successfully integrated into a unified CLI toolkit with a modular, scalable architecture.

## Current Project Structure

```
SecurityToolbox/
├── bsot.py                          # Main CLI entry point
│
├── commands/                        # Command modules
│   ├── data_commands/               # ✅ NEW: Modular structure
│   │   ├── __init__.py
│   │   ├── url_decode.py
│   │   ├── base64_decode.py
│   │   ├── hex_decode.py
│   │   └── email_header.py
│   │
│   ├── data.py                      # Old monolithic (can be removed)
│   ├── network.py                   # Network commands (monolithic)
│   ├── file.py                      # File commands (monolithic)
│   ├── auth.py                      # Auth commands (monolithic)
│   ├── system.py                    # System commands (monolithic)
│   ├── logs.py                      # Log commands (monolithic)
│   │
│   ├── *_commands/                  # Prepared for future modularization
│   │   └── (empty, ready for migration)
│   │
│   └── utils/                       # Shared utilities
│       ├── __init__.py
│       └── log_analyzer.py          # ✅ Moved from root
│
├── legacy/                          # ✅ OLD: Standalone scripts (wrappers)
│   ├── README.md
│   ├── overpermissive_files.py
│   ├── hidden_process_check.py
│   └── log_pattern_analyzer_wrapper.py
│
├── setup.py                         # Installation script
├── requirements.txt                 # Python dependencies
├── build_binary.sh                  # Binary compilation script
├── bsot.spec                        # PyInstaller spec file
│
├── README.md                        # Main documentation
├── USAGE.md                         # Quick reference guide
├── BUILD.md                         # Binary build instructions
├── REORGANIZATION.md                # Architecture explanation
└── PROJECT_SUMMARY.md               # This file
```

## What We Built

### 1. Unified CLI (`bsot`)
All security tools accessible through one command:
```bash
bsot <category> <command> [options]
```

### 2. Six Command Categories

#### File Security (`bsot file`)
- `permissions` - Scan for overly permissive files
- `suid-finder` - Find SUID/SGID binaries
- `cred-scan` - Detect hardcoded credentials
- `hash-check` - Calculate/verify file hashes

#### Network Security (`bsot network`)
- `ssl-check` - SSL/TLS certificate validation
- `port-scan` - Port scanning
- `web-headers` - HTTP security headers
- `dns-lookup` - DNS security (SPF/DMARC)

#### Data Analysis (`bsot data`) ✅ NOW MODULAR
- `url-decode` - URL decoding
- `base64-decode` - Base64 decoding
- `hex-decode` - Hex decoding
- `email-header` - Email header analysis

#### Authentication (`bsot auth`)
- `password-analyze` - Password strength
- `jwt-decode` - JWT token analysis
- `ssh-audit` - SSH config auditing

#### System Monitoring (`bsot system`)
- `process-check` - Detect suspicious processes

#### Log Analysis (`bsot logs`)
- `analyze` - Comprehensive log analysis

### 3. Key Features

✅ **Modular Architecture** - Data commands now in individual files
✅ **Backward Compatible** - Legacy scripts still work
✅ **Easy Installation** - `pip install -e .`
✅ **Binary Compilation** - Can build standalone executables
✅ **Consistent Interface** - All commands follow same pattern
✅ **Your Coding Style** - Clean, documented, practical

## Migration from Standalone Tools

| Old Tool | New Command |
|----------|-------------|
| `overpermissive_files.py` | `bsot file permissions` |
| `hidden_process_check.py` | `bsot system process-check` |
| `log_pattern_analyzer.py` | `bsot logs analyze` |

## Quick Start

### Installation
```bash
# From source
cd SecurityToolbox
pip install -e .

# Now use as:
bsot --help
```

### Running Commands
```bash
# File security
bsot file permissions /var/www
bsot file cred-scan . --extensions "py,js,env"

# Network security
bsot network ssl-check google.com
bsot network port-scan 192.168.1.1

# Data analysis
bsot data url-decode "Hello%20World"
bsot data base64-decode "SGVsbG8gV29ybGQ="

# Authentication
bsot auth password-analyze "MyP@ssw0rd"
bsot auth jwt-decode "eyJhbGc..."

# System monitoring
bsot system process-check --vt-api-key KEY

# Log analysis
bsot logs analyze /var/log/auth.log --focus brute_force
```

### Building Binary
```bash
# Quick build
chmod +x build_binary.sh
./build_binary.sh

# Manual build
pip install pyinstaller
pyinstaller bsot.spec

# Install globally
sudo cp dist/bsot /usr/local/bin/
```

## Architecture Highlights

### Modular Design (In Progress)
The `data_commands/` folder demonstrates the new architecture:
- Each command is its own file
- Easy to add new commands
- Better for testing and collaboration
- Scalable for future growth

### Future Improvements
Other categories can be modularized:
- `network_commands/` (ssl_check.py, port_scan.py, etc.)
- `file_commands/` (permissions.py, suid_finder.py, etc.)
- `auth_commands/` (password_analyze.py, jwt_decode.py, etc.)
- `system_commands/` (process_check.py)
- `logs_commands/` (analyze.py)

### Shared Utilities
Common code lives in `commands/utils/`:
- `log_analyzer.py` - Comprehensive log analysis engine

## Dependencies

```
click>=8.0.0       # CLI framework
requests>=2.25.0   # HTTP requests
dnspython>=2.1.0   # DNS lookups
```

Optional:
- `pyinstaller` - For binary compilation
- `nuitka` - Alternative compiler (better performance)

## Testing

```bash
# Test all command categories
python3 bsot.py --help
python3 bsot.py data --help
python3 bsot.py network --help
python3 bsot.py file --help
python3 bsot.py auth --help
python3 bsot.py system --help
python3 bsot.py logs --help

# Test specific commands
python3 bsot.py data url-decode "test%20string"
python3 bsot.py network ssl-check google.com
```

## Documentation

- **README.md** - Overview and installation
- **USAGE.md** - Command examples and quick reference
- **BUILD.md** - Binary compilation guide
- **REORGANIZATION.md** - Architecture explanation
- **legacy/README.md** - Migration guide

## Next Steps (Optional)

1. **Complete Modularization**: Migrate remaining categories to modular structure
2. **Remove Old Files**: Delete monolithic command files after migration
3. **Add Tests**: Create unit tests for each command
4. **CI/CD**: Set up automated testing and builds
5. **Distribution**: Publish to PyPI or create release packages
6. **More Tools**: Add additional security tools as needed

## Success Metrics

✅ All original tools integrated
✅ Unified CLI interface
✅ Modular architecture started
✅ Binary compilation ready
✅ Backward compatibility maintained
✅ Documentation complete
✅ Your coding style preserved

---

**BSOT is ready to use!** 🎉

All your existing security tools are now unified in one powerful CLI toolkit with room to grow.
