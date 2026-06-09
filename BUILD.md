# Building BSOT

## Quick Build

```bash
./build.sh
```

This creates a portable distribution at `dist/bsot_cx/` with fast startup times.

## Requirements

- Python 3.11+
- cx_Freeze (`pip install cx_Freeze`)

## Build Output

- **Distribution**: `dist/bsot_cx/`
- **Binary**: `dist/bsot_cx/bsot`
- **Size**: ~55 MB (includes all dependencies)
- **Startup**: ~1.5s first run, ~0.04s subsequent runs

## Installation

### Local User Installation (Recommended)

```bash
# Create directories
mkdir -p ~/.local/bin ~/.local/share

# Copy the distribution
cp -r dist/bsot_cx ~/.local/share/bsot

# Create symlink
ln -sf ~/.local/share/bsot/bsot ~/.local/bin/bsot

# Add to PATH (add to ~/.zshrc or ~/.bashrc)
export PATH="$HOME/.local/bin:$PATH"
```

### System-wide Installation

```bash
sudo cp -r dist/bsot_cx /opt/bsot
sudo ln -sf /opt/bsot/bsot /usr/local/bin/bsot
```

## Testing

```bash
# Test locally
./dist/bsot_cx/bsot --help
./dist/bsot_cx/bsot --version
./dist/bsot_cx/bsot data base64-decode 'SGVsbG8gV29ybGQ='

# Test installed version
bsot --help
bsot intel cve log4j --minimal
```

## Performance

cx_Freeze creates a directory-based distribution that macOS caches after first run:

| Run | Startup Time |
|-----|-------------|
| First run | ~1.5 seconds |
| Subsequent runs | ~0.04 seconds |

This is significantly faster than single-file solutions (PyInstaller onefile: ~3.5s every run).

## Platform Notes

### macOS
- Binary is automatically codesigned during build
- Quarantine attributes are removed
- Works on macOS 13.0+ (ARM and Intel)

### Linux
- Build on Linux for Linux binaries
- Expected startup: ~0.5-1 second

## Development vs Production

### Development (instant startup)
```bash
# Install in editable mode
pip install -e .

# Run directly
bsot <command>
```

### Production (standalone binary)
```bash
# Build
./build.sh

# Install
cp -r dist/bsot_cx ~/.local/share/bsot
ln -sf ~/.local/share/bsot/bsot ~/.local/bin/bsot

# Run
bsot <command>
```

## Distribution

Create a distributable archive:

```bash
cd dist
zip -r bsot-macos-$(date +%Y%m%d).zip bsot_cx/
```

Or tar:

```bash
cd dist
tar -czf bsot-macos-$(date +%Y%m%d).tar.gz bsot_cx/
```

## Troubleshooting

### "Cannot be opened because the developer cannot be verified"

The build script handles this automatically, but if needed:

```bash
xattr -cr dist/bsot_cx
codesign -s - -f dist/bsot_cx/bsot
```

### Build fails

Clean and rebuild:

```bash
rm -rf build dist/bsot_cx
./build.sh
```

### Slow first run

This is normal - macOS caches the libraries after first execution. Subsequent runs will be ~0.04s.
