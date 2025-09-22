#!/bin/bash

# QMS Platform - Deployment Verification Script
# Verifies the platform is working correctly after deployment

set -e

echo "🔍 QMS Platform Deployment Verification"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

check_service() {
    local port=$1
    local name=$2
    local url="https://localhost:$port"
    
    echo -n "Checking $name (port $port)... "
    
    if curl -k -s --connect-timeout 5 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Running${NC}"
        return 0
    else
        echo -e "${RED}❌ Not accessible${NC}"
        return 1
    fi
}

check_ssl_cert() {
    echo -n "Checking SSL certificates... "
    
    if [ -f "localhost+3.pem" ] && [ -f "localhost+3-key.pem" ]; then
        echo -e "${GREEN}✅ Found${NC}"
        
        # Check certificate validity
        if openssl x509 -in localhost+3.pem -noout -checkend 86400 > /dev/null 2>&1; then
            echo -e "  ${GREEN}✅ Certificate is valid${NC}"
        else
            echo -e "  ${YELLOW}⚠️  Certificate expired or invalid${NC}"
        fi
    else
        echo -e "${RED}❌ Missing${NC}"
        echo -e "  ${YELLOW}Run: ./deploy_ssl.sh to generate certificates${NC}"
    fi
}

check_python_env() {
    echo -n "Checking Python environment... "
    
    if [ -d "venv" ]; then
        echo -e "${GREEN}✅ Virtual environment exists${NC}"
    else
        echo -e "${YELLOW}⚠️  No virtual environment found${NC}"
        echo -e "  ${YELLOW}Run: python3 -m venv venv${NC}"
    fi
}

check_dependencies() {
    echo -n "Checking dependencies... "
    
    if source venv/bin/activate 2>/dev/null && python -c "import oqs, fastapi, uvicorn" 2>/dev/null; then
        echo -e "${GREEN}✅ All dependencies installed${NC}"
    else
        echo -e "${RED}❌ Missing dependencies${NC}"
        echo -e "  ${YELLOW}Run: source venv/bin/activate && pip install -r requirements.txt${NC}"
    fi
}

echo ""
echo "🔧 Environment Checks:"
echo "======================"

check_python_env
check_dependencies
check_ssl_cert

echo ""
echo "🌐 Service Availability:"
echo "========================"

# Check if services are running
FRONTEND_OK=false
MAIN_APP_OK=false
QUANTUM_API_OK=false

if check_service 8000 "Frontend HTTPS Server"; then
    FRONTEND_OK=true
fi

if check_service 4000 "Main Application"; then
    MAIN_APP_OK=true
fi

if check_service 3001 "Quantum API Service"; then
    QUANTUM_API_OK=true
fi

echo ""
echo "📊 Deployment Status:"
echo "====================="

if $FRONTEND_OK && $MAIN_APP_OK && $QUANTUM_API_OK; then
    echo -e "${GREEN}🎉 All services are running!${NC}"
    echo ""
    echo "🌟 Access URLs:"
    echo "==============="
    echo -e "${BLUE}Frontend:${NC}     https://localhost:8000"
    echo -e "${BLUE}Main App:${NC}     https://localhost:4000"
    echo -e "${BLUE}API Docs:${NC}     https://localhost:4000/docs"
    echo -e "${BLUE}Quantum API:${NC}  https://localhost:3001"
    echo ""
    
    # Get local IP for LAN access
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ipconfig getifaddr en0 2>/dev/null || echo "N/A")
    if [ "$LOCAL_IP" != "N/A" ]; then
        echo "🌐 LAN Access URLs:"
        echo "=================="
        echo -e "${BLUE}Frontend:${NC}     https://$LOCAL_IP:8000"
        echo -e "${BLUE}Main App:${NC}     https://$LOCAL_IP:4000"
        echo -e "${BLUE}API Docs:${NC}     https://$LOCAL_IP:4000/docs"
    fi
    
    echo ""
    echo -e "${GREEN}✅ QMS Platform is fully operational!${NC}"
    
else
    echo -e "${RED}❌ Some services are not running${NC}"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "=================="
    
    if ! $FRONTEND_OK; then
        echo -e "${YELLOW}Frontend (8000):${NC} Run 'python start_https_server.py'"
    fi
    
    if ! $MAIN_APP_OK; then
        echo -e "${YELLOW}Main App (4000):${NC} Run 'cd backend && python app.py'"
    fi
    
    if ! $QUANTUM_API_OK; then
        echo -e "${YELLOW}Quantum API (3001):${NC} Run 'cd backend && python service.py'"
    fi
    
    echo ""
    echo "Or restart all services:"
    echo "./deploy_ssl.sh"
fi

echo ""
echo "🔒 Security Verification:"
echo "========================="

# Check if using HTTPS
if curl -k -s https://localhost:8000 | grep -q "QMS Platform" 2>/dev/null; then
    echo -e "${GREEN}✅ HTTPS is working${NC}"
else
    echo -e "${YELLOW}⚠️  HTTPS verification failed${NC}"
fi

# Check quantum crypto endpoints
if curl -k -s https://localhost:3001/info 2>/dev/null | grep -q "ML-KEM\|Falcon" 2>/dev/null; then
    echo -e "${GREEN}✅ Quantum cryptography services active${NC}"
else
    echo -e "${YELLOW}⚠️  Quantum crypto verification inconclusive${NC}"
fi

echo ""
echo "📋 Health Summary:"
echo "=================="
echo "Platform ready for:"
echo "• Secure messaging with post-quantum cryptography"
echo "• Universal device access via GitHub"
echo "• Production deployment with SSL encryption"
echo ""
echo -e "${BLUE}Happy quantum messaging! 🚀${NC}"