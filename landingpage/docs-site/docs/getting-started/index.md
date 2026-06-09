# Getting Started

Welcome to BSOT! This guide will help you install, configure, and start using the toolkit.

---

## Guides

<div class="grid cards" markdown>

-   :material-download: **[Installation](installation.md)**

    ---

    Install BSOT via pip or download standalone binaries.

-   :material-cog: **[Configuration](configuration.md)**

    ---

    Set up API keys and customize BSOT behavior.

-   :material-rocket-launch: **[Quick Start](quick-start.md)**

    ---

    Get up and running in 5 minutes.

</div>

---

## System Requirements

- **Python**: 3.9 or higher (for pip installation)
- **OS**: macOS, Linux, Windows
- **Memory**: 256MB minimum
- **Disk**: 100MB for installation

---

## Quick Install

=== "pip"

    ```bash
    pip install bsot
    ```

=== "Binary"

    Download from [GitHub Releases](https://github.com/yourusername/bsot/releases):

    ```bash
    # macOS
    curl -LO https://github.com/yourusername/bsot/releases/latest/download/bsot-macos
    chmod +x bsot-macos
    sudo mv bsot-macos /usr/local/bin/bsot

    # Linux
    curl -LO https://github.com/yourusername/bsot/releases/latest/download/bsot-linux
    chmod +x bsot-linux
    sudo mv bsot-linux /usr/local/bin/bsot
    ```

=== "From Source"

    ```bash
    git clone https://github.com/yourusername/bsot.git
    cd bsot
    pip install -e .
    ```

---

## Verify Installation

```bash
bsot --version
```

---

## Next Steps

1. [Configure API keys](configuration.md) for threat intelligence
2. Follow the [Quick Start](quick-start.md) tutorial
3. Explore [Use Cases](../use-cases/index.md) for real-world examples
