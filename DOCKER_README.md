# 🐳 Docker Deployment Guide - PQCTransitSecure

## Overview

This Docker setup containerizes the PQCTransitSecure platform for easy deployment across any platform while keeping `liboqs` as a local build requirement (due to platform-specific compilation needs).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Docker Network                         │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Frontend   │  │   Main App   │  │   Quantum    │  │
│  │   :8000      │◄─┤   :4000      │◄─┤   Service    │  │
│  │   (HTTPS)    │  │   (HTTPS)    │  │   :3001      │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│         │                 │                 │           │
│         └─────────────────┴─────────────────┘           │
│                      Volumes                             │
│         ┌────────────────────────────────┐              │
│         │  liboqs/ (mounted, not copied) │              │
│         │  liboqs-python/ (mounted)      │              │
│         │  *.pem (SSL certificates)      │              │
│         │  *.db (database)               │              │
│         │  *.log (logs)                  │              │
│         └────────────────────────────────┘              │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

### Required on ALL platforms:
- **Docker Desktop** or **Docker Engine** (20.10+)
- **Docker Compose** (v2.0+)
- **mkcert** (for SSL certificates)

### Required BEFORE Docker deployment:
- **liboqs** must be built locally on each machine
- **liboqs-python** must be available

## Quick Start

### 1. First-Time Setup (Build liboqs)

**Linux/macOS:**
```bash
./setup_complete.sh
```

**Windows:**
```powershell
.\setup_complete_windows.bat
```

This builds `liboqs` locally (required once per machine).

### 2. Deploy with Docker

**Linux/macOS:**
```bash
./deploy_docker.sh
```

**Windows:**
```powershell
docker-compose up -d
```

### 3. Access the Platform

- **Frontend:** https://localhost:8000
- **Main App API:** https://localhost:4000
- **Quantum Service:** https://localhost:3001

## Manual Docker Commands

### Build containers:
```bash
docker-compose build
```

### Start services:
```bash
docker-compose up -d
```

### Stop services:
```bash
docker-compose down
```

### View logs:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f quantum-service
docker-compose logs -f main-app
docker-compose logs -f frontend
```

### Restart services:
```bash
docker-compose restart
```

### Check service status:
```bash
docker-compose ps
```

### Access container shell:
```bash
docker exec -it pqc-main-app bash
```

## What's Included in Docker

### ✅ Containerized (platform-independent):
- Python 3.11 runtime
- All Python dependencies (FastAPI, SQLAlchemy, etc.)
- Backend services (app.py, service.py)
- Frontend server (start_https_server.py)
- Frontend files (index.html, sw.js, etc.)

### ❌ NOT Containerized (local build required):
- **liboqs** - Mounted as read-only volume
- **liboqs-python** - Mounted as read-only volume
- SSL certificates - Mounted from host
- Database - Persisted on host
- Logs - Written to host

## Why liboqs is NOT in Docker

**Reason:** liboqs requires platform-specific compilation and performs better when built natively for each CPU architecture. Docker containers may run on different architectures (x86, ARM, etc.), making a universal liboqs build impractical.

**Solution:** Build liboqs locally once, then Docker mounts it as a volume.

## Volume Mounts

The `docker-compose.yml` defines these mounts:

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `./liboqs/` | `/app/liboqs/` | Quantum crypto library (read-only) |
| `./liboqs-python/` | `/app/liboqs-python/` | Python bindings (read-only) |
| `./localhost+3.pem` | `/app/localhost+3.pem` | SSL certificate |
| `./localhost+3-key.pem` | `/app/localhost+3-key.pem` | SSL private key |
| `./qms_quantum.db` | `/app/qms_quantum.db` | Database file |
| `./quantum_ssl.log` | `/app/quantum_ssl.log` | Quantum service logs |
| `./app_ssl.log` | `/app/app_ssl.log` | Main app logs |
| `./frontend_ssl.log` | `/app/frontend_ssl.log` | Frontend logs |

## Environment Variables

Set in `docker-compose.yml`:

- `PYTHONUNBUFFERED=1` - Real-time log output
- `SSL_CERT_FILE` - SSL certificate path
- `SSL_KEY_FILE` - SSL private key path
- `QUANTUM_API` - Quantum service URL
- `LD_LIBRARY_PATH` - liboqs library path (Linux)
- `DYLD_LIBRARY_PATH` - liboqs library path (macOS)

## Network Configuration

All services run on the `pqc-network` bridge network:
- Services can communicate using container names (e.g., `quantum-service:3001`)
- External access via mapped ports (8000, 4000, 3001)

## Health Checks

Each service has health checks:
- **Quantum Service:** `curl -f https://localhost:3001/health`
- **Main App:** `curl -f https://localhost:4000/health`
- **Frontend:** `curl -f -k https://localhost:8000`

Check health status:
```bash
docker ps
```

## Troubleshooting

### Container won't start:
```bash
# Check logs
docker-compose logs quantum-service

# Common issue: liboqs not built
# Solution: Run ./setup_complete.sh first
```

### Permission errors:
```bash
# Fix volume permissions
chmod -R 755 liboqs/ liboqs-python/
```

### SSL certificate errors:
```bash
# Regenerate certificates
mkcert localhost 127.0.0.1 ::1
```

### Port already in use:
```bash
# Find process using port
lsof -i :8000

# Stop existing services
./stop_docker.sh
```

### Rebuild from scratch:
```bash
# Stop and remove everything
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

## Platform-Specific Notes

### macOS:
- Uses `DYLD_LIBRARY_PATH` for liboqs
- Docker Desktop required

### Linux:
- Uses `LD_LIBRARY_PATH` for liboqs
- Can use Docker Engine

### Windows:
- Use `docker-compose` commands in PowerShell
- May need to enable WSL2 backend
- Build liboqs with Visual Studio Build Tools first

## Deployment to Remote Servers

### Transfer to remote machine:
```bash
# 1. Clone repository
git clone https://github.com/Rahul4356/qsm.git
cd qsm

# 2. Build liboqs locally
./setup_complete.sh

# 3. Deploy with Docker
./deploy_docker.sh
```

### Using Docker Registry (optional):
```bash
# Build and push image
docker-compose build
docker tag pqc-main-app:latest your-registry/pqc-main-app:latest
docker push your-registry/pqc-main-app:latest

# On remote machine
docker pull your-registry/pqc-main-app:latest
```

## Production Considerations

### Security:
- Use proper SSL certificates (not self-signed mkcert)
- Set secure environment variables
- Restrict port access with firewall

### Performance:
- Increase container resources if needed
- Use production-grade database (PostgreSQL)
- Enable Docker logging drivers

### Monitoring:
```bash
# Resource usage
docker stats

# Container health
docker-compose ps
```

## Comparison: Docker vs Native

| Aspect | Docker | Native (./deploy_ssl.sh) |
|--------|--------|--------------------------|
| **Setup Time** | Fast (after liboqs built) | Fast |
| **Portability** | High | Medium |
| **Performance** | ~5% overhead | Native speed |
| **Isolation** | Excellent | None |
| **Updates** | Easy (rebuild image) | Easy (git pull) |
| **Dependencies** | Contained | System-wide |

## Support

For issues:
1. Check logs: `docker-compose logs -f`
2. Verify liboqs: `ls -la liboqs/build/lib/`
3. Test native: `./deploy_ssl.sh` (should work first)
4. Open GitHub issue: https://github.com/Rahul4356/qsm/issues

## Summary

✅ **Use Docker when:**
- Deploying to multiple environments
- Need consistent dependencies
- Want isolated services
- Testing/development

✅ **Use Native when:**
- Maximum performance needed
- Single development machine
- Debugging liboqs issues

Both methods work perfectly and don't interfere with each other!
