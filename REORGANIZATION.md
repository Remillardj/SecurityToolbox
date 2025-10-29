# BSOT Reorganization Plan

## Current Structure

```
SecurityToolbox/
├── bsot.py                    # Main CLI entry point
├── commands/
│   ├── __init__.py
│   ├── data.py               # All data commands in one file
│   ├── network.py            # All network commands in one file
│   ├── file.py               # All file commands in one file
│   ├── auth.py               # All auth commands in one file
│   ├── system.py             # All system commands in one file
│   ├── logs.py               # All logs commands in one file
│   └── utils/
│       ├── __init__.py
│       └── log_analyzer.py   # Shared log analysis logic
└── legacy/                    # Old standalone scripts (wrappers)
    ├── overpermissive_files.py
    ├── hidden_process_check.py
    └── log_pattern_analyzer_wrapper.py
```

## New Modular Structure (In Progress)

```
SecurityToolbox/
├── bsot.py                    # Main CLI entry point
├── commands/
│   ├── __init__.py
│   ├── data_commands/         # Data category
│   │   ├── __init__.py        # Exports data_group
│   │   ├── url_decode.py      # Individual command
│   │   ├── base64_decode.py   # Individual command
│   │   ├── hex_decode.py      # Individual command
│   │   └── email_header.py    # Individual command
│   ├── network_commands/      # Network category
│   │   ├── __init__.py        # Exports network_group
│   │   ├── ssl_check.py
│   │   ├── port_scan.py
│   │   ├── web_headers.py
│   │   └── dns_lookup.py
│   ├── file_commands/         # File category
│   │   ├── __init__.py        # Exports file_group
│   │   ├── permissions.py
│   │   ├── suid_finder.py
│   │   ├── cred_scan.py
│   │   └── hash_check.py
│   ├── auth_commands/         # Auth category
│   │   ├── __init__.py        # Exports auth_group
│   │   ├── password_analyze.py
│   │   ├── jwt_decode.py
│   │   └── ssh_audit.py
│   ├── system_commands/       # System category
│   │   ├── __init__.py        # Exports system_group
│   │   └── process_check.py
│   ├── logs_commands/         # Logs category
│   │   ├── __init__.py        # Exports logs_group
│   │   └── analyze.py
│   └── utils/                 # Shared utilities
│       ├── __init__.py
│       └── log_analyzer.py
└── legacy/                    # Old standalone scripts
    ├── README.md
    ├── overpermissive_files.py
    ├── hidden_process_check.py
    └── log_pattern_analyzer_wrapper.py
```

## Benefits of New Structure

1. **Modularity**: Each command is its own file, easier to maintain
2. **Scalability**: Easy to add new commands without bloating existing files
3. **Organization**: Clear separation of concerns
4. **Testing**: Individual commands can be tested in isolation
5. **Collaboration**: Multiple people can work on different commands without conflicts

## Migration Status

### ✅ Completed
- Created `commands/data_commands/` with individual command files
- Moved `log_pattern_analyzer.py` to `commands/utils/log_analyzer.py`
- Created `legacy/` folder for old standalone scripts
- Updated legacy scripts to be backward-compatible wrappers

### 🔄 In Progress
- Data commands modular structure (completed)
- Need to complete network, file, auth, system, logs categories

### ⏳ TODO
- Create modular structure for remaining categories
- Update `bsot.py` to import from new structure
- Update documentation
- Update build scripts
- Test all commands in new structure
- Remove old monolithic command files

## How Each __init__.py Works

Example from `commands/data_commands/__init__.py`:

```python
"""Data encoding/decoding commands"""

import click
from .url_decode import url_decode
from .base64_decode import base64_decode
from .hex_decode import hex_decode
from .email_header import email_header

@click.group('data')
def data_group():
    """Data encoding/decoding and analysis tools"""
    pass

# Register individual commands
data_group.add_command(url_decode)
data_group.add_command(base64_decode)
data_group.add_command(hex_decode)
data_group.add_command(email_header)
```

This allows `bsot.py` to simply import `data_group` and all commands are automatically registered.

## Usage (No Change for End Users)

The command-line interface remains exactly the same:

```bash
python3 bsot.py data url-decode "Hello%20World"
python3 bsot.py network ssl-check google.com
python3 bsot.py file permissions /var/www
```

Users won't notice any difference - this is purely an internal reorganization for better code maintainability.
