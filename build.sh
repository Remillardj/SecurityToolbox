#!/bin/bash
# Build BSOT using cx_Freeze - Creates a portable binary distribution
#
# This creates a standalone distribution with fast startup times.
# First run: ~1.5s, subsequent runs: ~0.04s (macOS caches libraries)

set -e

echo "🔨 Building BSOT with cx_Freeze..."
echo ""

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Clean previous build
rm -rf build dist/bsot_cx dist/bsot

# Build with cx_Freeze
python3 setup_cx.py build_exe --build-exe=dist/bsot_cx

echo ""
if [ -d "dist/bsot_cx" ] && [ -f "dist/bsot_cx/bsot" ]; then
    echo "✅ Build complete!"
    echo ""
    
    # Optimize for macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "Optimizing for macOS..."
        xattr -cr dist/bsot_cx 2>/dev/null && echo "  ✅ Removed quarantine attributes"
        codesign -s - -f dist/bsot_cx/bsot 2>/dev/null && echo "  ✅ Codesigned binary"
        echo ""
    fi

    # Test the binary
    echo "Testing binary..."
    ./dist/bsot_cx/bsot --version
    echo ""

    # Show size
    echo "📦 Distribution size:"
    du -sh dist/bsot_cx
    echo ""

    echo "🚀 To install:"
    echo "   mkdir -p ~/.local/bin ~/.local/share"
    echo "   cp -r dist/bsot_cx ~/.local/share/bsot"
    echo "   ln -sf ~/.local/share/bsot/bsot ~/.local/bin/bsot"
    echo ""
    echo "   # Make sure ~/.local/bin is in your PATH"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "📝 Test commands:"
    echo "   bsot --help"
    echo "   bsot intel cve log4j --minimal"
    echo "   bsot data base64-decode 'SGVsbG8gV29ybGQ='"
else
    echo "❌ Build failed! Check errors above."
    exit 1
fi
