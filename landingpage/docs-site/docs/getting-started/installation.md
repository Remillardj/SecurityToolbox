# Installation

Multiple ways to install BSOT depending on your needs.

---

## pip (Recommended)

The easiest way to install BSOT is via pip:

```bash
pip install bsot
```

This installs BSOT and all dependencies.

### Upgrade

```bash
pip install --upgrade bsot
```

### Uninstall

```bash
pip uninstall bsot
```

---

## Standalone Binary

Pre-built binaries are available for systems without Python.

### macOS

```bash
# Download
curl -LO https://github.com/yourusername/bsot/releases/latest/download/bsot-macos

# Make executable
chmod +x bsot-macos

# Move to PATH
sudo mv bsot-macos /usr/local/bin/bsot

# Verify
bsot --version
```

### Linux

```bash
# Download
curl -LO https://github.com/yourusername/bsot/releases/latest/download/bsot-linux

# Make executable
chmod +x bsot-linux

# Move to PATH
sudo mv bsot-linux /usr/local/bin/bsot

# Verify
bsot --version
```

### Windows

1. Download `bsot.exe` from [GitHub Releases](https://github.com/yourusername/bsot/releases)
2. Move to a directory in your PATH
3. Open Command Prompt and run `bsot --version`

---

## From Source

For development or the latest features:

```bash
# Clone repository
git clone https://github.com/yourusername/bsot.git
cd bsot

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install in development mode
pip install -e .

# Verify
bsot --version
```

---

## Docker

Run BSOT in a container:

```bash
# Pull image
docker pull yourusername/bsot:latest

# Run
docker run --rm -it yourusername/bsot bsot --help

# With file access
docker run --rm -it -v $(pwd):/data yourusername/bsot bsot file hash /data/sample.exe
```

---

## Dependencies

BSOT requires these Python packages (installed automatically):

- `click` - CLI framework
- `rich` - Terminal formatting
- `httpx` - HTTP client
- `pyyaml` - YAML parsing
- `python-magic` - File type detection
- `pefile` - PE file analysis
- `yara-python` - YARA scanning
- `ssdeep` - Fuzzy hashing

Optional dependencies:

- `openai` - AI-powered analysis
- `anthropic` - Claude AI integration

---

## Troubleshooting

### "Command not found"

Ensure the installation directory is in your PATH:

```bash
# Check where pip installs scripts
python -m site --user-base

# Add to PATH (Linux/macOS)
export PATH="$PATH:$(python -m site --user-base)/bin"

# Add to shell config for persistence
echo 'export PATH="$PATH:$(python -m site --user-base)/bin"' >> ~/.bashrc
```

### Permission errors

Use a virtual environment or install for your user only:

```bash
pip install --user bsot
```

### python-magic issues on macOS

Install libmagic:

```bash
brew install libmagic
```

### python-magic issues on Windows

Download the DLL from [python-magic-bin](https://pypi.org/project/python-magic-bin/):

```bash
pip install python-magic-bin
```

---

## Next Steps

- [Configure API keys](configuration.md)
- [Quick Start tutorial](quick-start.md)
