#!/bin/bash
# Build BSOT using Nuitka - Creates a single portable binary
#
# This creates a true standalone binary that you can copy anywhere.
# Startup time: ~3 seconds
# No dependencies required on target system.

echo "Building BSOT with Nuitka..."
echo "Creating single portable binary..."
echo ""

# Clean previous build
rm -rf bsot.build bsot.dist bsot.onefile-build dist/bsot

# Build with Nuitka with optimizations to reduce startup time
python3 -m nuitka \
    --standalone \
    --onefile \
    --follow-imports \
    --include-package=commands \
    --include-package-data=commands \
    --enable-plugin=anti-bloat \
    --assume-yes-for-downloads \
    --onefile-tempdir-spec='{CACHE_DIR}/{COMPANY}/{PRODUCT}/{VERSION}' \
    --company-name=BSOT \
    --product-name=bsot \
    --product-version=1.0.0 \
    --disable-ccache \
    --output-filename=bsot \
    --output-dir=dist \
    bsot.py

echo ""
if [ -f "dist/bsot" ]; then
    echo "✅ Nuitka build complete!"
    echo "Binary location: dist/bsot"

    # Optimize for macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo ""
        echo "Optimizing for macOS..."
        xattr -cr dist/bsot 2>/dev/null && echo "  ✅ Removed quarantine attributes"
        codesign -s - -f dist/bsot 2>/dev/null && echo "  ✅ Codesigned binary"
    fi

    # Test the binary
    echo ""
    echo "Testing binary..."
    ./dist/bsot --version

    # Clean up build artifacts
    echo ""
    echo "Cleaning up build artifacts..."
    rm -rf dist/bsot.dist dist/bsot.build dist/bsot.onefile-build
    echo "  ✅ Removed temporary build files"

    echo ""
    echo "Test the binary:"
    echo "  ./dist/bsot --help"
    echo "  ./dist/bsot data base64-decode 'SGVsbG8gV29ybGQ='"
    echo ""
    echo "To install globally:"
    echo "  sudo cp dist/bsot /usr/local/bin/"
    echo ""
    echo "Final binary:"
    ls -lh dist/bsot | awk '{print "  " $9 " - " $5}'
else
    echo "❌ Build failed! Check errors above."
    exit 1
fi
