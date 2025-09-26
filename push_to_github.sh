#!/bin/bash

# QMS Platform - Push to GitHub Script
# Run this script after creating your GitHub repository

echo "🚀 QMS Platform - GitHub Push Helper"
echo "==================================="

# Check if username is provided
if [ -z "$1" ]; then
    echo "Usage: ./push_to_github.sh YOUR_GITHUB_USERNAME"
    echo ""
    echo "Example: ./push_to_github.sh rahulsemwal"
    echo ""
    echo "Make sure you've created the repository 'qms-platform' on GitHub first!"
    echo "Visit: https://github.com/new"
    exit 1
fi

USERNAME=$1
REPO_URL="https://github.com/$USERNAME/qms-platform.git"

echo "GitHub Username: $USERNAME"
echo "Repository URL: $REPO_URL"
echo ""

# Check if remote already exists
if git remote get-url origin &> /dev/null; then
    echo "⚠️  Remote 'origin' already exists:"
    git remote get-url origin
    echo ""
    read -p "Do you want to update it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git remote set-url origin "$REPO_URL"
        echo "✅ Remote URL updated"
    else
        echo "❌ Cancelled"
        exit 1
    fi
else
    echo "📡 Adding remote origin..."
    git remote add origin "$REPO_URL"
    echo "✅ Remote origin added"
fi

# Ensure we're on main branch
echo "🌿 Setting branch to main..."
git branch -M main

# Push to GitHub
echo "🚀 Pushing to GitHub..."
if git push -u origin main; then
    echo ""
    echo "🎉 SUCCESS! Your QMS Platform is now on GitHub!"
    echo "=========================================="
    echo ""
    echo "📂 Repository URL: https://github.com/$USERNAME/qms-platform"
    echo "🌐 Clone from anywhere: git clone https://github.com/$USERNAME/qms-platform.git"
    echo ""
    echo "🔗 Share this repository URL to give others access to your quantum messaging platform!"
    echo ""
    echo "🚀 Universal Deployment Command:"
    echo "git clone https://github.com/$USERNAME/qms-platform.git && cd qms-platform && ./deploy_ssl.sh"
else
    echo ""
    echo "❌ Push failed. Common solutions:"
    echo "1. Make sure you've created the repository on GitHub"
    echo "2. Check your GitHub credentials"
    echo "3. Verify the repository name is 'qms-platform'"
    echo "4. Ensure you have push permissions"
fi