# Building BSOT

## Quick Build

```bash
./build.sh
```

This creates a **single portable binary** at `dist/bsot` that you can copy to any server.

## Requirements

- Python 3.11+
- Nuitka (automatically installed by build script)

## Build Output

- **Binary**: `dist/bsot`
- **Size**: ~8.5 MB
- **Startup**: ~3 seconds
- **Dependencies**: None (fully self-contained)

## Testing the Binary

```bash
# Test locally
./dist/bsot --help
./dist/bsot data base64-decode 'SGVsbG8gV29ybGQ='

# Test portability
cp dist/bsot /tmp/
/tmp/bsot --version
```

## Installation

### Local User Installation
```bash
mkdir -p ~/bin
cp dist/bsot ~/bin/
# Add ~/bin to PATH if needed
```

### System-wide Installation
```bash
sudo cp dist/bsot /usr/local/bin/
```

### Deploy to Remote Server
```bash
scp dist/bsot user@server:/path/to/destination/
ssh user@server '/path/to/destination/bsot --help'
```

## Build Details

The build process uses **Nuitka** to:
1. Compile Python code to C for native execution
2. Create a single executable with all dependencies bundled
3. No Python interpreter required on target system
4. Automatically optimize for macOS (remove quarantine, codesign)

### Performance Benefits

- **Native compiled**: ~3 second startup (vs PyInstaller's 10 seconds)
- **Lazy imports**: Commands load only when invoked
- **True binary**: No extraction overhead after first run

## Platform-Specific Notes

### macOS
- Binary requires macOS 13.0+ (x86_64)
- First run may be slower (~5s) due to Gatekeeper scanning
- Subsequent runs are ~3 seconds

### Linux
- Build on Linux for Linux binaries
- Expected startup: ~1-2 seconds (faster than macOS)

### Windows
- Not currently supported (but Nuitka can build Windows binaries)

## Troubleshooting

### Slow startup on first run
This is normal - macOS Gatekeeper scans the binary on first execution. After the first run, it caches the security check.

### "Cannot be opened because the developer cannot be verified"
The build script automatically handles this, but if you still see this error:
```bash
xattr -cr dist/bsot
codesign -s - -f dist/bsot
```

### Build fails
Clean and rebuild:
```bash
rm -rf bsot.build bsot.dist bsot.onefile-build dist/
./build.sh
```

### Import errors
If you add new command modules, ensure they're in the `commands/` package and rebuild.

## Development vs Production

### Development (faster iteration)
```bash
python3 bsot.py <command>
```

### Production (standalone binary)
```bash
./dist/bsot <command>
```

## Distribution

The `dist/bsot` binary is fully self-contained. Just copy it anywhere:

```bash
# Create distributable archive
tar -czf bsot-macos-$(date +%Y%m%d).tar.gz dist/bsot

# Or just copy the binary directly
cp dist/bsot /path/to/destination/
```

No installation, dependencies, or Python required on the target system!
