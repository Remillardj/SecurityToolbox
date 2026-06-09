#!/bin/bash
# Build script for BSOT marketing + documentation site
# Run from the landingpage/ directory
# Outputs everything to ./site/ for static hosting

set -e

echo "🔨 Building BSOT site..."

# Ensure site directory structure exists
mkdir -p site/{css,js,assets,docs}

# Copy marketing site files
echo "📄 Copying marketing site..."
cp marketing/index.html site/
cp marketing/css/custom.css site/css/
cp marketing/js/main.js site/js/
cp -r marketing/assets/* site/assets/ 2>/dev/null || true

# Build MkDocs documentation using venv
echo "📚 Building documentation..."
cd docs-site

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "   Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate and install dependencies
source .venv/bin/activate
.venv/bin/pip install -r requirements.txt -q

# Build docs
.venv/bin/mkdocs build

deactivate
cd ..

echo ""
echo "✅ Build complete!"
echo ""
echo "📁 Output structure:"
echo "   site/"
echo "   ├── index.html        (Marketing homepage)"
echo "   ├── css/custom.css"
echo "   ├── js/main.js"
echo "   ├── assets/"
echo "   └── docs/             (MkDocs documentation)"
echo ""
echo "🚀 To preview locally:"
echo "   cd site && python3 -m http.server 8080"
echo ""
echo "☁️  To deploy to Cloudflare Pages:"
echo "   Upload the 'site' folder as your static site root"

