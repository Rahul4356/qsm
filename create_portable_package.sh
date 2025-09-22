#!/bin/bash
# QMS Platform - Portable Deployment Package Creator
# Creates a self-contained package for easy transfer to other devices

echo "📦 Creating QMS Portable Deployment Package"
echo "============================================"

# Create deployment directory
DEPLOY_DIR="qms-portable-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DEPLOY_DIR"

echo "📁 Creating deployment structure..."

# Copy essential files
cp -r backend "$DEPLOY_DIR/"
cp index.html "$DEPLOY_DIR/"
cp start_https_server.py "$DEPLOY_DIR/"
cp deploy_ssl.sh "$DEPLOY_DIR/"

# Copy SSL certificates if they exist
if [[ -f "localhost+3.pem" && -f "localhost+3-key.pem" ]]; then
    cp localhost+3.pem "$DEPLOY_DIR/"
    cp localhost+3-key.pem "$DEPLOY_DIR/"
    echo "✅ SSL certificates included"
else
    echo "⚠️  SSL certificates not found - will be generated on target device"
fi

# Copy liboqs if it exists
if [[ -d "liboqs" ]]; then
    echo "📚 Copying liboqs library (this may take a moment)..."
    cp -r liboqs "$DEPLOY_DIR/"
    echo "✅ liboqs library included"
fi

# Copy liboqs-python if it exists
if [[ -d "liboqs-python" ]]; then
    cp -r liboqs-python "$DEPLOY_DIR/"
    echo "✅ liboqs-python included"
fi

# Create requirements.txt
cat > "$DEPLOY_DIR/requirements.txt" << EOF
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
cryptography>=41.0.0
sqlalchemy>=2.0.0
pydantic>=2.4.0
bcrypt>=4.0.0
PyJWT>=2.8.0
httpx>=0.25.0
python-multipart>=0.0.6
websockets>=11.0.0
EOF

# Create setup script for target device
cat > "$DEPLOY_DIR/setup.sh" << 'EOF'
#!/bin/bash
# QMS Platform - Target Device Setup Script
# Run this script on your production device

echo "🚀 Setting up QMS Platform on this device"
echo "=========================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    echo "Please install Python 3.8+ and run this script again"
    exit 1
fi

echo "✅ Python 3 detected: $(python3 --version)"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

# Install liboqs-python if not included
if [[ ! -d "liboqs-python" ]]; then
    echo "📥 Installing liboqs-python..."
    pip install liboqs-python
fi

# Check if mkcert is available for SSL
if command -v mkcert &> /dev/null; then
    echo "✅ mkcert detected"
    if [[ ! -f "localhost+3.pem" ]]; then
        echo "🔒 Generating SSL certificates..."
        # Get local IP
        LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ifconfig | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | sed 's/addr://')
        if [[ -n "$LOCAL_IP" ]]; then
            mkcert localhost 127.0.0.1 ::1 "$LOCAL_IP"
            echo "✅ SSL certificates created for localhost and $LOCAL_IP"
        else
            mkcert localhost 127.0.0.1 ::1
            echo "✅ SSL certificates created for localhost"
        fi
    fi
else
    echo "⚠️  mkcert not found - install for SSL support:"
    echo "   macOS: brew install mkcert"
    echo "   Linux: apt install libnss3-tools && wget mkcert binary"
fi

# Make scripts executable
chmod +x deploy_ssl.sh
chmod +x start_https_server.py

echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "🚀 To start the platform:"
echo "   ./deploy_ssl.sh"
echo ""
echo "🌐 Or start individual services:"
echo "   source venv/bin/activate"
echo "   python3 backend/service.py  # Quantum API"
echo "   python3 backend/app.py      # Main App"
echo "   python3 start_https_server.py  # Frontend"
echo ""
echo "📋 Default URLs:"
echo "   Frontend: https://localhost:8000"
echo "   Main App: https://localhost:4000"
echo "   API: https://localhost:3001"
EOF

# Create README for the package
cat > "$DEPLOY_DIR/README.md" << EOF
# QMS Platform - Portable Deployment Package

## Quick Start

1. **Transfer this entire folder** to your target device
2. **Run setup**: \`chmod +x setup.sh && ./setup.sh\`
3. **Start platform**: \`./deploy_ssl.sh\`

## What's Included

- ✅ Complete QMS Platform source code
- ✅ Backend API services (FastAPI)
- ✅ Frontend web interface
- ✅ SSL/HTTPS support
- ✅ Quantum cryptography (liboqs)
- ✅ Automated setup script
- ✅ Deployment scripts

## System Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **mkcert** (optional, for SSL certificates)

## Installation Options

### Option 1: Automated Setup (Recommended)
\`\`\`bash
chmod +x setup.sh
./setup.sh
./deploy_ssl.sh
\`\`\`

### Option 2: Manual Setup
\`\`\`bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 backend/service.py &
python3 backend/app.py &
python3 start_https_server.py
\`\`\`

## URLs After Deployment

- **Frontend**: https://localhost:8000
- **Main App**: https://localhost:4000  
- **Quantum API**: https://localhost:3001

## Features

- 🔒 **SSL/TLS Encryption**
- 🔐 **ML-KEM-768** (Quantum-resistant key exchange)
- ✍️ **Falcon-512** (Quantum-resistant signatures)
- 💬 **Real-time messaging**
- 📱 **Mobile-friendly interface**
- 🌐 **LAN access support**

## Troubleshooting

1. **Python not found**: Install Python 3.8+
2. **SSL issues**: Install mkcert for local certificates
3. **Port conflicts**: Modify ports in deploy_ssl.sh
4. **Dependencies**: Run \`pip install -r requirements.txt\`

Generated: $(date)
EOF

# Make setup script executable
chmod +x "$DEPLOY_DIR/setup.sh"

# Create the package archive
echo "🗜️  Creating portable archive..."
tar -czf "${DEPLOY_DIR}.tar.gz" "$DEPLOY_DIR"

echo ""
echo "✅ Portable deployment package created!"
echo "======================================"
echo ""
echo "📦 Package: ${DEPLOY_DIR}.tar.gz"
echo "📁 Folder: ${DEPLOY_DIR}/"
echo ""
echo "🚀 To deploy on target device:"
echo "   1. Transfer: ${DEPLOY_DIR}.tar.gz"
echo "   2. Extract: tar -xzf ${DEPLOY_DIR}.tar.gz"
echo "   3. Setup: cd ${DEPLOY_DIR} && ./setup.sh"
echo "   4. Deploy: ./deploy_ssl.sh"
echo ""
echo "📋 Package size: $(du -h "${DEPLOY_DIR}.tar.gz" | cut -f1)"
echo "📋 Contains: $(find "$DEPLOY_DIR" -type f | wc -l) files"