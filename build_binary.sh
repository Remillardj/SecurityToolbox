#!/bin/bash
# Build BSOT into a standalone binary using PyInstaller

echo "Building BSOT binary..."

# Install PyInstaller if not already installed
pip install pyinstaller

# Build using the spec file (recommended)
echo "Building with bsot.spec..."
pyinstaller bsot.spec

echo ""
# Check for onedir build (dist/bsot/bsot) or onefile build (dist/bsot)
if [ -f "dist/bsot/bsot" ]; then
    echo "✅ Build complete! (onedir mode)"
    echo "Binary location: dist/bsot/bsot"

    # Optimize for macOS - remove quarantine and codesign
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo ""
        echo "Optimizing for macOS..."
        xattr -cr dist/bsot/ 2>/dev/null && echo "  ✅ Removed quarantine attributes"
        codesign -s - -f dist/bsot/bsot 2>/dev/null && echo "  ✅ Codesigned binary"
        codesign -s - -f dist/bsot/_internal/Python 2>/dev/null && echo "  ✅ Codesigned Python framework"
    fi

    echo ""
    echo "Test the binary:"
    echo "  ./dist/bsot/bsot --help"
    echo "  ./dist/bsot/bsot data url-decode 'Hello%20World'"
    echo ""
    echo "To create a symlink for easy access:"
    echo "  sudo ln -sf $(pwd)/dist/bsot/bsot /usr/local/bin/bsot"
    echo ""
    echo "Or add to PATH:"
    echo "  export PATH=\$PATH:$(pwd)/dist/bsot"
elif [ -f "dist/bsot" ]; then
    echo "✅ Build complete! (onefile mode)"
    echo "Binary location: dist/bsot"

    # Optimize for macOS - remove quarantine and codesign
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo ""
        echo "Optimizing for macOS..."
        xattr -cr dist/bsot 2>/dev/null && echo "  ✅ Removed quarantine attributes"
        codesign -s - -f dist/bsot 2>/dev/null && echo "  ✅ Codesigned binary"
    fi

    echo ""
    echo "Test the binary:"
    echo "  ./dist/bsot --help"
    echo "  ./dist/bsot data url-decode 'Hello%20World'"
    echo ""
    echo "To install globally:"
    echo "  sudo cp dist/bsot /usr/local/bin/"
    echo ""
    echo "Or add to PATH:"
    echo "  export PATH=\$PATH:$(pwd)/dist"
else
    echo "❌ Build failed! Check errors above."
    exit 1
fi
