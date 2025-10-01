#!/bin/bash
# Stop Docker containers for PQCTransitSecure Platform

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Use docker-compose or docker compose
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

echo "🛑 Stopping PQCTransitSecure Docker containers..."
$DOCKER_COMPOSE down

echo "✅ All containers stopped and removed"
