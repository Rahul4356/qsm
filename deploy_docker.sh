#!/bin/bash
# Docker deployment script for PQCTransitSecure Platform
# Uses Docker Compose to orchestrate all services

set -e

echo "🐳 PQCTransitSecure Docker Deployment"
echo "======================================"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found!"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found!"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Use docker-compose or docker compose
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

# Check for liboqs
if [ ! -d "liboqs" ] || [ ! -d "liboqs-python" ]; then
    echo "⚠️  WARNING: liboqs or liboqs-python directory not found!"
    echo "The quantum service requires liboqs to be built locally."
    echo ""
    echo "To build liboqs, run:"
    echo "  ./setup_complete.sh"
    echo ""
    read -p "Continue anyway? (y/N): " continue
    if [[ ! $continue =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for SSL certificates
if [ ! -f "localhost+3.pem" ] || [ ! -f "localhost+3-key.pem" ]; then
    echo "⚠️  SSL certificates not found!"
    echo "Creating certificates with mkcert..."
    
    if command -v mkcert &> /dev/null; then
        mkcert localhost 127.0.0.1 ::1
        echo "✅ SSL certificates created"
    else
        echo "❌ mkcert not found!"
        echo "Install mkcert or create certificates manually:"
        echo "  brew install mkcert (macOS)"
        echo "  apt install libnss3-tools && download mkcert (Linux)"
        exit 1
    fi
fi

echo ""
echo "🔨 Building Docker images..."
$DOCKER_COMPOSE build

echo ""
echo "🚀 Starting services..."
$DOCKER_COMPOSE up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 5

# Check service status
echo ""
echo "📊 Service Status:"
$DOCKER_COMPOSE ps

echo ""
echo "🎉 Docker Deployment Complete!"
echo "=============================="
echo ""
echo "🔒 Access URLs:"
echo "   Frontend:     https://localhost:8000"
echo "   Main App:     https://localhost:4000"
echo "   Quantum API:  https://localhost:3001"
echo ""
echo "📝 View logs:"
echo "   All services:      $DOCKER_COMPOSE logs -f"
echo "   Quantum service:   $DOCKER_COMPOSE logs -f quantum-service"
echo "   Main app:          $DOCKER_COMPOSE logs -f main-app"
echo "   Frontend:          $DOCKER_COMPOSE logs -f frontend"
echo ""
echo "🛑 Stop services:"
echo "   $DOCKER_COMPOSE down"
echo ""
echo "🔄 Restart services:"
echo "   $DOCKER_COMPOSE restart"
echo ""
echo "✅ Platform is running!"
