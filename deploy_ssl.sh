#!/bin/bash
# SSL Deployment Script for QMS Platform
# Starts all services with HTTPS encryption

cd "/Users/rahulsemwal/Desktop/ducc beta testing"

echo "🔒 Starting QMS Platform with SSL Encryption"
echo "=============================================="

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
    echo "Creating certificates with mkcert..."
    mkcert localhost 127.0.0.1 ::1 10.237.138.1
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
echo "🌐 LAN Access:"
echo "🔒 Frontend:     https://10.237.138.1:8000"
echo "🔒 Main App:     https://10.237.138.1:4000"
echo "🔒 Quantum API:  https://10.237.138.1:3001"
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
echo "🛑 To stop all: pkill -f 'python.*backend'; pkill -f 'start_https_server'"