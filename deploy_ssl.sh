#!/bin/bash
# SSL Deployment Script for QMS Platform
# Starts all services with HTTPS encryption

# Get the script directory (works on any device)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔒 Starting QMS Platform with SSL Encryption"
echo "=============================================="
echo "📁 Working Directory: $SCRIPT_DIR"

# Detect local IP address dynamically
echo "🌐 Detecting network configuration..."
LOCAL_IP=""

# Try different methods to get local IP
if command -v route >/dev/null 2>&1; then
    # macOS/Linux with route command
    LOCAL_IP=$(route get default 2>/dev/null | grep interface | awk '{print $2}' | xargs ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
fi

# Fallback method 1: Check common network interfaces
if [[ -z "$LOCAL_IP" ]]; then
    LOCAL_IP=$(ifconfig 2>/dev/null | grep -A 1 "en0\|eth0\|wlan0" | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
fi

# Fallback method 2: Any non-localhost IP
if [[ -z "$LOCAL_IP" ]]; then
    LOCAL_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
fi

# Clean up IP (remove addr: prefix if present)
LOCAL_IP=$(echo "$LOCAL_IP" | sed 's/addr://')

if [[ -n "$LOCAL_IP" ]]; then
    echo "✅ Detected Local IP: $LOCAL_IP"
else
    echo "⚠️  Could not detect local IP - using localhost only"
    LOCAL_IP="localhost"
fi

# Kill any existing processes
echo "🛑 Stopping existing services..."
pkill -f "python.*service.py" 2>/dev/null || true
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "start_https_server.py" 2>/dev/null || true
lsof -ti:8000,3001,4000 | xargs kill -9 2>/dev/null || true

sleep 2

# Check SSL certificates
if [[ ! -f "localhost+3.pem" || ! -f "localhost+3-key.pem" ]]; then
    echo "❌ SSL certificates not found!"
    echo "🔒 Creating certificates with mkcert..."
    
    if command -v mkcert >/dev/null 2>&1; then
        if [[ "$LOCAL_IP" != "localhost" ]]; then
            echo "📜 Generating certificates for localhost, 127.0.0.1, ::1, and $LOCAL_IP"
            mkcert localhost 127.0.0.1 ::1 "$LOCAL_IP"
        else
            echo "📜 Generating certificates for localhost only"
            mkcert localhost 127.0.0.1 ::1
        fi
    else
        echo "❌ mkcert not found! Please install mkcert for SSL support"
        echo "   macOS: brew install mkcert"
        echo "   Linux: apt install libnss3-tools && download mkcert binary"
        echo "   Then run: mkcert -install"
        exit 1
    fi
fi

echo "✅ SSL certificates verified"

# Start Quantum Service (Port 3001)
echo "🚀 Starting Quantum Crypto Service (HTTPS:3001)..."
DYLD_LIBRARY_PATH="./liboqs/build/lib:$DYLD_LIBRARY_PATH" \
PYTHONPATH="./liboqs-python:$PYTHONPATH" \
nohup python3 backend/service.py > quantum_ssl.log 2>&1 &
QUANTUM_PID=$!

sleep 3

# Start Main App (Port 4000)
echo "🚀 Starting QMS Main Application (HTTPS:4000)..."
nohup python3 backend/app.py > app_ssl.log 2>&1 &
APP_PID=$!

sleep 3

# Start Frontend (Port 8000)
echo "🚀 Starting HTTPS Frontend Server (HTTPS:8000)..."
nohup python3 start_https_server.py > frontend_ssl.log 2>&1 &
FRONTEND_PID=$!

sleep 2

echo ""
echo "🎉 SSL Deployment Complete!"
echo "=========================="
echo "🔒 Frontend:     https://localhost:8000"
echo "🔒 Main App:     https://localhost:4000"
echo "🔒 Quantum API:  https://localhost:3001"
echo ""

if [[ "$LOCAL_IP" != "localhost" && -n "$LOCAL_IP" ]]; then
    echo "🌐 LAN Access (Share with others):"
    echo "🔒 Frontend:     https://$LOCAL_IP:8000"
    echo "🔒 Main App:     https://$LOCAL_IP:4000"
    echo "🔒 Quantum API:  https://$LOCAL_IP:3001"
    echo ""
    echo "📱 Mobile/Remote Access:"
    echo "   Share this link: https://$LOCAL_IP:8000"
else
    echo "⚠️  LAN access not available - local IP detection failed"
    echo "💡 Manual setup: Create certificates with your IP using mkcert"
fi

echo ""
echo "📋 Process IDs:"
echo "   Quantum Service: $QUANTUM_PID"
echo "   Main App: $APP_PID"
echo "   Frontend: $FRONTEND_PID"
echo ""
echo "📝 Logs:"
echo "   tail -f quantum_ssl.log"
echo "   tail -f app_ssl.log"
echo "   tail -f frontend_ssl.log"
echo ""
echo "🔧 Network Info:"
echo "   Device IP: ${LOCAL_IP:-'Not detected'}"
echo "   Certificates: $(ls -1 *.pem 2>/dev/null | wc -l | tr -d ' ') SSL files"
echo ""
echo "🛑 To stop all: pkill -f 'python.*backend'; pkill -f 'start_https_server'"