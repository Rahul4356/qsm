#!/bin/bash

# QMS Platform - Release Management Script
# Helps create tagged releases for the platform

set -e

VERSION=${1:-"1.0.0"}
MESSAGE=${2:-"QMS Platform Release"}

echo "🏷️  QMS Platform Release Creator"
echo "================================="
echo "Version: $VERSION"
echo "Message: $MESSAGE"
echo ""

# Validate version format (basic semver check)
if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ Invalid version format. Use semantic versioning (e.g., 1.0.0)"
    echo "Usage: ./create_release.sh [version] [message]"
    echo "Example: ./create_release.sh 1.0.0 'Initial release'"
    exit 1
fi

# Check if git repository exists
if [ ! -d ".git" ]; then
    echo "❌ Not a git repository. Run setup_github.sh first."
    exit 1
fi

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "⚠️  Uncommitted changes detected. Committing them first..."
    git add .
    git commit -m "Pre-release cleanup for v$VERSION"
fi

# Create annotated tag
echo "🏷️  Creating release tag v$VERSION..."
git tag -a "v$VERSION" -m "$MESSAGE

Release v$VERSION of QMS Platform

Features:
- Post-quantum cryptography (ML-KEM-768 + Falcon-512)
- SSL/TLS encryption with automatic certificate generation
- Universal device access and portable deployment
- Production-ready quantum messaging platform
- Comprehensive documentation and setup scripts

Deployment:
./deploy_ssl.sh

Access URLs:
- Frontend: https://localhost:8000
- API: https://localhost:4000  
- Docs: https://localhost:4000/docs

For universal access, clone and deploy on any device."

# Push tags to remote if remote exists
if git remote get-url origin &> /dev/null; then
    echo "🚀 Pushing release to GitHub..."
    git push origin main
    git push origin "v$VERSION"
    echo "✅ Release v$VERSION pushed to GitHub"
    
    # Show GitHub release creation command
    echo ""
    echo "🎉 Create GitHub Release:"
    echo "========================"
    echo "Visit: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\([^/]*\/[^/]*\)\.git/\1/')/releases/new"
    echo "Or use GitHub CLI:"
    echo "gh release create v$VERSION --title \"QMS Platform v$VERSION\" --notes \"$MESSAGE\""
else
    echo "⚠️  No remote configured. Tag created locally."
    echo "Run 'git push origin v$VERSION' after setting up remote."
fi

# Show current tags
echo ""
echo "📋 Available Releases:"
echo "====================="
git tag -l | sort -V | tail -5

echo ""
echo "✅ Release v$VERSION created successfully!"
echo "🌟 Your quantum messaging platform is ready for distribution!"