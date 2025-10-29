# Building BSOT as a Binary

There are several ways to compile BSOT into a standalone binary.

## Option 1: PyInstaller (Recommended)

PyInstaller creates a single executable that bundles Python and all dependencies.

### Quick Build

```bash
# Make the build script executable
chmod +x build_binary.sh

# Run the build
./build_binary.sh
```

The binary will be created in `dist/bsot`.

### Manual Build

```bash
# Install PyInstaller
pip install pyinstaller

# Build with spec file (recommended)
pyinstaller bsot.spec

# Or build with command line options
pyinstaller --onefile --name bsot bsot.py
```

### Install the Binary

```bash
# Copy to system location (requires sudo)
sudo cp dist/bsot /usr/local/bin/

# Or add to PATH
export PATH=$PATH:$(pwd)/dist
```

### Test the Binary

```bash
./dist/bsot --help
./dist/bsot data url-decode "Hello%20World"
./dist/bsot network ssl-check google.com
```

## Option 2: Nuitka (Better Performance)

Nuitka compiles Python to C for better performance and smaller binaries.

```bash
# Install Nuitka
pip install nuitka

# Build standalone binary
python -m nuitka --standalone --onefile \
    --include-package=commands \
    --include-module=log_pattern_analyzer \
    --output-dir=dist \
    --output-filename=bsot \
    bsot.py

# The binary will be in dist/bsot
```

## Option 3: cx_Freeze

Cross-platform alternative to PyInstaller.

```bash
# Install cx_Freeze
pip install cx_Freeze

# Create a setup file
cat > setup_freeze.py << 'EOF'
from cx_Freeze import setup, Executable

setup(
    name="bsot",
    version="1.0.0",
    description="Blue Security Ops Toolkit",
    executables=[Executable("bsot.py", target_name="bsot")],
    options={
        "build_exe": {
            "packages": ["commands", "click", "requests", "dns"],
            "include_files": ["log_pattern_analyzer.py"]
        }
    }
)
EOF

# Build
python setup_freeze.py build

# Binary will be in build/
```

## Platform-Specific Notes

### macOS
- The binary will only work on macOS
- May need to sign the binary: `codesign -s - dist/bsot`
- Can use `--osx-bundle-identifier` with PyInstaller

### Linux
- The binary will only work on Linux
- Consider building in a Docker container for portability
- Can use `--hidden-import` for missing modules

### Windows
- Use PyInstaller or Nuitka on Windows
- May need to add `--console` flag
- Can create installers with NSIS or Inno Setup

## Distribution

### Single Binary
```bash
# Just distribute the binary from dist/
tar -czf bsot-macos-arm64.tar.gz dist/bsot
```

### With Dependencies Bundled
```bash
# PyInstaller already bundles everything
# Just share the dist/bsot file
```

## Troubleshooting

### Missing Modules
If you get import errors, add hidden imports:
```bash
pyinstaller --onefile \
    --hidden-import=missing_module \
    bsot.py
```

### Large Binary Size
To reduce size:
```bash
# Use UPX compression
pyinstaller --onefile --upx-dir=/path/to/upx bsot.py

# Exclude unnecessary packages
pyinstaller --onefile --exclude-module pytest bsot.py
```

### Runtime Errors
Test with verbose mode:
```bash
./dist/bsot --help
```

Check for missing data files and add them:
```bash
pyinstaller --onefile --add-data "file.txt:." bsot.py
```

## Development vs Production

### Development (faster iteration)
```bash
python3 bsot.py <command>
```

### Production (standalone binary)
```bash
./dist/bsot <command>
```

## Binary Size Comparison

- **PyInstaller**: ~15-30 MB (includes Python interpreter)
- **Nuitka**: ~10-20 MB (compiled to C)
- **cx_Freeze**: ~15-25 MB

Choose based on your needs:
- **PyInstaller**: Easiest, most compatible
- **Nuitka**: Best performance
- **cx_Freeze**: Good cross-platform support
