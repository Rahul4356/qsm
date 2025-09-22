#!/bin/bash

# QMS Platform - GitHub Setup Script
# This script prepares the repository for GitHub upload

set -e

echo "🚀 QMS Platform - GitHub Repository Setup"
echo "========================================="

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Check if gh CLI is available (optional)
if command -v gh &> /dev/null; then
    GH_CLI_AVAILABLE=true
    echo "✅ GitHub CLI detected"
else
    GH_CLI_AVAILABLE=false
    echo "ℹ️  GitHub CLI not available (optional)"
fi

# Initialize git repository if not already initialized
if [ ! -d ".git" ]; then
    echo "📁 Initializing Git repository..."
    git init
    echo "✅ Git repository initialized"
else
    echo "✅ Git repository already exists"
fi

# Add all files to staging
echo "📦 Adding files to staging..."
git add .

# Check if there are any changes to commit
if git diff --staged --quiet; then
    echo "ℹ️  No changes to commit"
else
    # Commit changes
    echo "💾 Committing changes..."
    git commit -m "Initial QMS Platform release with SSL encryption and universal access

- Post-quantum cryptography: ML-KEM-768 + Falcon-512
- SSL/TLS encryption with mkcert certificates  
- Universal device access and portable deployment
- Comprehensive documentation and setup scripts
- Production-ready quantum messaging platform"
    echo "✅ Changes committed"
fi

# Check if remote origin exists
if git remote get-url origin &> /dev/null; then
    echo "✅ Remote origin already configured"
    REMOTE_EXISTS=true
else
    echo "⚠️  No remote origin configured"
    REMOTE_EXISTS=false
fi

echo ""
echo "🎯 GitHub Repository Options:"
echo "==============================="

if [ "$GH_CLI_AVAILABLE" = true ] && [ "$REMOTE_EXISTS" = false ]; then
    echo "Option 1: Create repository using GitHub CLI (Recommended)"
    echo "1️⃣  Run: gh repo create qms-platform --public --description \"Quantum-secure messaging platform with SSL encryption\""
    echo ""
fi

echo "Option 2: Manual GitHub Repository Creation"
echo "1️⃣  Go to: https://github.com/new"
echo "2️⃣  Repository name: qms-platform"
echo "3️⃣  Description: Quantum-secure messaging platform with SSL encryption"
echo "4️⃣  Set to Public"
echo "5️⃣  Don't initialize with README (we already have one)"
echo "6️⃣  Click 'Create repository'"
echo ""

if [ "$REMOTE_EXISTS" = false ]; then
    echo "Option 3: Add remote and push manually"
    echo "After creating the repository on GitHub:"
    echo "git remote add origin https://github.com/YOUR_USERNAME/qms-platform.git"
    echo "git branch -M main"
    echo "git push -u origin main"
    echo ""
fi

echo "🔧 Quick Setup Commands:"
echo "========================"

if [ "$GH_CLI_AVAILABLE" = true ] && [ "$REMOTE_EXISTS" = false ]; then
    echo "# Create and push to GitHub (with gh CLI):"
    echo "gh repo create qms-platform --public --description \"Quantum-secure messaging platform with SSL encryption\""
    echo "git push -u origin main"
    echo ""
fi

echo "# Clone from any device after upload:"
echo "git clone https://github.com/YOUR_USERNAME/qms-platform.git"
echo "cd qms-platform"
echo "./deploy_ssl.sh"
echo ""

echo "📋 Repository Checklist:"
echo "========================"
echo "✅ README.md - Comprehensive documentation"
echo "✅ .gitignore - Proper exclusions"
echo "✅ setup.sh - Environment setup"
echo "✅ deploy_ssl.sh - SSL deployment"
echo "✅ create_portable_package.sh - Portable deployment"
echo "✅ requirements.txt - Dependencies"
echo "✅ Source code - Complete platform"
echo ""

echo "🌟 Next Steps:"
echo "============="
echo "1. Create GitHub repository (see options above)"
echo "2. Push code to GitHub"
echo "3. Test clone and deploy on another device"
echo "4. Share repository URL for universal access"
echo ""

echo "🎊 Your QMS Platform is ready for GitHub!"
echo "Deploy once, access everywhere. 🚀"