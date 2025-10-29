# Performance Optimization for BSOT Binary

## The Problem

The binary takes 10+ seconds to run due to macOS Gatekeeper security checks on unsigned binaries.

```bash
time dist/bsot --help
# 0.14s user 0.07s system 2% cpu 10.066 total  ← 10 seconds is the Gatekeeper delay!
```

## Solutions (Fastest to Slowest)

### 1. Sign the Binary (FASTEST - Instant startup)

```bash
# Self-sign the binary
codesign --force --deep --sign - dist/bsot

# Now test
time dist/bsot --help
# Should be ~0.2s total!
```

**Benefits:**
- Instant startup (no Gatekeeper delay)
- Works with --onefile
- Small binary size (8.3MB)

**Note:** This creates a self-signed binary (not distributed, just for your own use).

### 2. Use Directory Mode Instead of Single File

Faster extraction, but larger footprint:

```bash
# Edit bsot.spec and rebuild
# Change: onefile=True → onedir=True

# Or rebuild with:
pyinstaller --onedir bsot.spec

# Then run from:
./dist/bsot/bsot --help
```

**Benefits:**
- Faster startup (~2-3 seconds instead of 10+)
- No signing needed

**Drawbacks:**
- Creates a folder instead of single file
- Harder to distribute

### 3. Use Nuitka (FASTEST COMPILATION)

Nuitka compiles to C for much better performance:

```bash
# Install Nuitka
pip install nuitka

# Compile (takes 5-10 minutes)
python -m nuitka --standalone --onefile \
    --include-package=commands \
    --include-module=commands.data_commands \
    --include-module=commands.utils.log_analyzer \
    --output-dir=dist \
    --output-filename=bsot \
    bsot.py

# Sign it
codesign --force --deep --sign - dist/bsot

# Now it starts INSTANTLY
time dist/bsot --help
# ~0.1s total!
```

**Benefits:**
- Fastest runtime performance
- Smaller binary size
- Instant startup when signed

**Drawbacks:**
- Longer compilation time
- More complex build process

### 4. Add to Allowed Apps

Tell macOS to trust it:

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine dist/bsot

# Or add to /Applications
sudo cp dist/bsot /Applications/
```

### 5. Install as Python Package (RECOMMENDED FOR DEVELOPMENT)

Skip the binary entirely during development:

```bash
# Install in editable mode
pip install -e .

# Now use directly (instant startup)
bsot --help
bsot data url-decode "test"

# Only build binary for distribution
```

**Benefits:**
- Instant startup (no binary extraction)
- Easier to debug
- Changes take effect immediately

**Use binary for:**
- Distribution to users without Python
- Isolated environments
- Production deployments

## Recommended Workflow

### During Development
```bash
# Install as package
pip install -e .

# Use directly
bsot data url-decode "test"
```

### For Distribution
```bash
# Build binary
./build_binary.sh

# Sign it
codesign --force --deep --sign - dist/bsot

# Test
./dist/bsot --help  # Should be ~0.2s

# Distribute
tar -czf bsot-macos.tar.gz dist/bsot
```

## Performance Comparison

| Method | Startup Time | Size | Best For |
|--------|-------------|------|----------|
| Python direct | 0.1s | N/A | Development |
| pip install -e | 0.1s | N/A | Development |
| Signed binary (onefile) | 0.2s | 8.3MB | Distribution |
| Unsigned binary (onefile) | 10s | 8.3MB | ❌ Avoid |
| Nuitka (signed) | 0.1s | ~5MB | Production |
| PyInstaller (onedir) | 2-3s | ~25MB | Alternative |

## Quick Fix (Right Now)

```bash
# Sign your binary
codesign --force --deep --sign - dist/bsot

# Test it
time dist/bsot --help
# Should be fast now!
```

This self-signing tells macOS you trust the binary, removing the Gatekeeper delay.

## For Real Distribution

For distributing to other users, you'd need:
1. Apple Developer account ($99/year)
2. Developer ID certificate
3. Notarization through Apple

For personal/internal use, self-signing is perfect and free.
