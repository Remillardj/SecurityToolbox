# Legacy Scripts

These are backward-compatible wrappers for the old standalone scripts. They now call the unified BSOT toolkit.

## Migration Guide

### overpermissive_files.py
**Old:**
```bash
python3 overpermissive_files.py /var/www
```

**New:**
```bash
python3 bsot.py file permissions /var/www
# or after install:
bsot file permissions /var/www
```

### hidden_process_check.py
**Old:**
```bash
python3 hidden_process_check.py
```

**New:**
```bash
python3 bsot.py system process-check
# or after install:
bsot system process-check
```

### log_pattern_analyzer.py
**Old:**
```bash
python3 log_pattern_analyzer.py /var/log/auth.log --focus brute_force
```

**New:**
```bash
python3 bsot.py logs analyze /var/log/auth.log --focus brute_force
# or after install:
bsot logs analyze /var/log/auth.log --focus brute_force
```

## Why the Change?

All tools have been unified under the BSOT (Blue Security Ops Toolkit) CLI for:
- Consistent interface across all tools
- Easier installation and distribution
- Single binary compilation
- Better organization and maintainability

## Backward Compatibility

The wrapper scripts in this folder still work and will call the new BSOT commands, so your existing scripts and workflows won't break.
