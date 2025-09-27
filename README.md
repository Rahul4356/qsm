# 🔐 QMS Platform - Quantum Messaging System

A production-ready, quantum-secure messaging platform using post-quantum cryptography with SSL encryption and universal device access.

![QMS Platform](https://img.shields.io/badge/Quantum-Secure-blue) ![SSL](https://img.shields.io/badge/SSL-Enabled-green) ![License](https://img.shields.io/badge/License-MIT-yellow) ![Python](https://img.shields.io/badge/Python-3.8+-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-Latest-red)

## 🚀 Features

- **🔐 Post-Quantum Cryptography**: ML-KEM-768 (Kyber768) + Falcon-512
- **🔒 SSL/TLS Encryption**: Full HTTPS/WSS support for production
- **💬 Real-time Messaging**: WebSocket-based secure communication
- **🌐 Universal Access**: Deploy to any device, access from anywhere
- **📱 Mobile-Friendly**: Responsive web interface
- **⚡ High Performance**: FastAPI backend with SQLAlchemy
- **🛡️ Security Headers**: HSTS, XSS protection, content security
- **📦 Portable Deployment**: One-command setup and deployment

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Main App      │    │  Quantum API    │
│   (Port 8000)   │◄──►│   (Port 4000)   │◄──►│   (Port 3001)   │
│   HTTPS Server  │    │   FastAPI       │    │   liboqs        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
           │                       │                       │
           └───────────── SSL/TLS Encryption ──────────────┘
```

## 📦 Quick Start

### ⚠️ **IMPORTANT: liboqs Quantum Library Required**

This platform uses **REAL quantum cryptography** (not simulation) and requires the liboqs library to be compiled and installed.

### 🐧 Linux/macOS Setup

#### Option 1: Complete Automated Setup (Recommended)
```bash
# One-command setup with liboqs compilation
git clone https://github.com/Rahul4356/qsm.git && cd qsm && chmod +x setup_complete.sh && ./setup_complete.sh

# Then deploy
./deploy_ssl.sh
```

#### Option 2: Step-by-Step Setup
```bash
git clone https://github.com/Rahul4356/qsm.git
cd qsm

# Complete setup with liboqs compilation
chmod +x setup_complete.sh
./setup_complete.sh

# Deploy with SSL
./deploy_ssl.sh
```

#### Option 3: Simple Setup (Basic Dependencies Only)
```bash
git clone https://github.com/Rahul4356/qsm.git
cd qsm
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./deploy_ssl.sh
```

### 🪟 Windows Setup

#### Prerequisites:
- **Visual Studio Build Tools 2019/2022** (for liboqs compilation)
- **CMake** (`winget install Kitware.CMake`)
- **Python 3.8+** (`winget install Python.Python.3`)

#### Option 1: Complete Setup with liboqs (Recommended)
```powershell
# Complete setup with quantum library compilation
git clone https://github.com/Rahul4356/qsm.git && cd qsm && .\setup_complete_windows.bat

# Then deploy
.\deploy_ssl_windows.bat
```

#### Option 2: Simple Setup (Basic Dependencies)
```powershell
git clone https://github.com/Rahul4356/qsm.git && cd qsm && .\setup_windows.bat && .\deploy_ssl_windows.bat
```

#### Option 3: HTTP Fallback (No SSL)
```powershell
git clone https://github.com/Rahul4356/qsm.git && cd qsm && .\setup_windows.bat && .\deploy_http_windows.bat
```

### Option 3: Portable Package (For Production Devices)

```bash
# Create portable package
./create_portable_package.sh

# Transfer qms-platform-portable.tar.gz to target device
# Extract and run:
tar -xzf qms-platform-portable.tar.gz
cd qms-platform
./deploy.sh
```

## 🌐 Access URLs

After deployment, access your quantum messaging platform:

### Local Access
- **Frontend**: `https://localhost:8000`
- **Main App**: `https://localhost:4000`
- **API Documentation**: `https://localhost:4000/docs`
- **Quantum API**: `https://localhost:3001`

### LAN Access (Replace with your IP)
- **Frontend**: `https://[YOUR_IP]:8000`
- **Main App**: `https://[YOUR_IP]:4000`
- **API Documentation**: `https://[YOUR_IP]:4000/docs`

## 🔧 System Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **mkcert** (for SSL certificates)
- **liboqs** (for quantum cryptography)

### Installing Dependencies

#### macOS
```bash
# Install mkcert
brew install mkcert

# Install liboqs
brew install liboqs

# Initialize mkcert
mkcert -install
```

#### Ubuntu/Debian
```bash
# Install mkcert
sudo apt update
sudo apt install libnss3-tools
curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v*-linux-amd64
sudo mv mkcert-v*-linux-amd64 /usr/local/bin/mkcert

# Install liboqs
sudo apt install liboqs-dev

# Initialize mkcert
mkcert -install
```

#### Windows
```powershell
# Install mkcert using Chocolatey
choco install mkcert

# Or download from GitHub releases
# Initialize mkcert
mkcert -install
```

## 🚀 Deployment Options

### Local Development
```bash
./deploy_ssl.sh
```

### Production Device
```bash
# Create portable package
./create_portable_package.sh

# Deploy to production device
scp qms-platform-portable.tar.gz user@target-device:~/
ssh user@target-device
tar -xzf qms-platform-portable.tar.gz
cd qms-platform
./deploy.sh
```

### Docker Deployment (Coming Soon)
```bash
docker-compose up -d
```

## 🔐 Security Features

### Post-Quantum Cryptography
- **ML-KEM-768**: NIST Level 3 quantum-resistant key exchange
- **Falcon-512**: NIST Level 1 quantum-resistant digital signatures
- **ECDSA-P256**: Classical wrapper for hybrid security
- **AES-256-GCM**: Authenticated encryption for message content

### Transport Security
- **TLS 1.2/1.3**: Modern transport encryption
- **Perfect Forward Secrecy**: Session key isolation
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy headers
- **Certificate Validation**: Automatic SSL certificate generation

### Application Security
- **JWT Authentication**: Secure session management
- **Rate Limiting**: API protection
- **Input Validation**: XSS and injection prevention
- **Secure Headers**: OWASP security standards

## 📁 Project Structure

```
qms-platform/
├── backend/
│   ├── app.py                      # Main application server (SSL-enabled)
│   ├── service.py                  # Quantum crypto service (SSL-enabled)
│   └── requirements.txt            # Python dependencies
├── quantum-secure-comm/            # Core platform files
│   ├── index.html                  # Enhanced web interface
│   ├── app.py                      # Main backend application
│   ├── service.py                  # Quantum service backend
│   └── requirements.txt            # Platform dependencies
├── liboqs/                         # Quantum cryptography library
├── liboqs-python/                  # Python bindings for liboqs
├── setup.sh                        # Environment setup script
├── deploy_ssl.sh                   # SSL deployment script
├── create_portable_package.sh      # Portable package creator
├── start_https_server.py           # HTTPS frontend server
├── .gitignore                      # Git exclusions
└── README.md                       # This documentation
```

## 🔧 Configuration

### Environment Variables

```bash
# API Configuration
export QUANTUM_API_URL="https://localhost:3001"
export JWT_SECRET="your-secret-key"

# SSL Configuration
export SSL_CERT_FILE="localhost+3.pem"
export SSL_KEY_FILE="localhost+3-key.pem"

# Database
export DATABASE_URL="sqlite:///./qms_quantum.db"

# Network Configuration
export HOST="0.0.0.0"  # For LAN access
export PORT="4000"
```

### SSL Certificate Configuration

The platform automatically generates SSL certificates using mkcert:

```bash
# Certificates are generated for:
# - localhost
# - 127.0.0.1
# - ::1 (IPv6 localhost)
# - Your local IP address
```

## 🔧 API Documentation

### Authentication Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Token refresh
- `POST /api/auth/logout` - User logout

### Messaging Endpoints
- `GET /api/messages/` - Get message history
- `POST /api/messages/` - Send encrypted message
- `DELETE /api/messages/{id}` - Delete message
- `WebSocket /ws` - Real-time communication

### Quantum Crypto Endpoints
- `GET /api/quantum/info` - Service information
- `POST /api/quantum/keygen` - Generate ML-KEM-768 key pair
- `POST /api/quantum/encrypt` - Encrypt data with quantum keys
- `POST /api/quantum/decrypt` - Decrypt quantum-encrypted data
- `POST /api/quantum/sign` - Create Falcon-512 digital signature

### System Endpoints
- `GET /health` - Health check
- `GET /api/version` - API version information
- `GET /docs` - Interactive API documentation

## 🚨 Troubleshooting

### Common Issues

**1. SSL Certificate Errors**
```bash
# Regenerate certificates with local IP
./deploy_ssl.sh

# Or manually regenerate
mkcert localhost 127.0.0.1 ::1 $(hostname -I | awk '{print $1}')
```

**2. Port Already in Use**
```bash
# Kill existing processes
pkill -f "python.*backend"
lsof -ti:8000,3001,4000 | xargs kill -9

# Check port usage
netstat -tulpn | grep -E ':(8000|3001|4000)'
```

**3. liboqs Not Found**
```bash
# Install liboqs-python
pip install liboqs-python

# For system-wide liboqs installation issues
sudo apt install liboqs-dev  # Ubuntu/Debian
brew install liboqs         # macOS
```

**4. Permission Denied on Scripts**
```bash
# Make scripts executable
chmod +x setup.sh deploy_ssl.sh create_portable_package.sh
```

**5. Remote Access Issues**
```bash
# Check firewall settings
sudo ufw allow 8000,3001,4000/tcp  # Ubuntu/Debian

# Verify IP address
ip route get 1.1.1.1 | awk '{print $7}'
```

## 🌐 Universal Device Access

### GitHub Repository Setup

1. **Create GitHub Repository**:
   ```bash
   gh repo create qms-platform --public
   git remote add origin https://github.com/yourusername/qms-platform.git
   ```

2. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Initial QMS Platform release"
   git push -u origin main
   ```

3. **Access from Any Device**:
   ```bash
   git clone https://github.com/yourusername/qms-platform.git
   cd qms-platform
   ./deploy_ssl.sh
   ```

### Cloud Deployment Options

- **AWS EC2**: Deploy with security groups for HTTPS
- **Google Cloud**: Use Compute Engine with firewall rules
- **DigitalOcean**: Droplet with UFW firewall configuration
- **Azure**: Virtual Machine with Network Security Groups

## 📱 Mobile Access

The platform is fully responsive and works on:
- **iOS Safari**: Full PWA support
- **Android Chrome**: Native app experience
- **Desktop Browsers**: Chrome, Firefox, Safari, Edge

## 🧪 Testing

### Run Unit Tests
```bash
source venv/bin/activate
python -m pytest tests/
```

### Security Testing
```bash
# SSL/TLS testing
nmap --script ssl-enum-ciphers -p 8000,3001,4000 localhost

# Port scanning
nmap -p 8000,3001,4000 localhost
```

## 📄 License

This project is licensed under the MIT License. See `LICENSE` file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 🙏 Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) for liboqs quantum cryptography
- [NIST](https://www.nist.gov/) for post-quantum cryptography standards
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- [mkcert](https://github.com/FiloSottile/mkcert) for local SSL certificate generation
- [SQLAlchemy](https://www.sqlalchemy.org/) for robust database management

## 📞 Support

For support, please:
1. Check the troubleshooting section above
2. Search existing GitHub issues
3. Create a new issue with detailed information
4. Include system information and error logs

---

**⚡ Built with quantum-resistant cryptography for the post-quantum era**

*Deploy once, access everywhere. Your quantum-secure messaging platform awaits.*