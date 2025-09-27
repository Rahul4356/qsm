#!/bin/bash
# Complete QMS Platform Setup with liboqs (Linux/macOS)
# Builds and installs liboqs quantum cryptography library

set -e

echo "🔐 QMS Platform Complete Setup with Quantum Cryptography"
echo "========================================================="

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    echo "🍎 Detected: macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    echo "🐧 Detected: Linux"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

# Check dependencies
echo "📋 Checking dependencies..."

# Check for required tools
MISSING_DEPS=()

if ! command -v cmake &> /dev/null; then
    MISSING_DEPS+=("cmake")
fi

if ! command -v make &> /dev/null; then
    MISSING_DEPS+=("make")
fi

if ! command -v git &> /dev/null; then
    MISSING_DEPS+=("git")
fi

if ! command -v python3 &> /dev/null; then
    MISSING_DEPS+=("python3")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo "❌ Missing dependencies: ${MISSING_DEPS[*]}"
    echo
    if [[ "$OS" == "macOS" ]]; then
        echo "Install with Homebrew:"
        echo "brew install ${MISSING_DEPS[*]}"
    else
        echo "Install with package manager:"
        echo "sudo apt update && sudo apt install -y ${MISSING_DEPS[*]} build-essential"
    fi
    exit 1
fi

echo "✅ All system dependencies found"

# Build liboqs
echo "🔨 Building liboqs quantum cryptography library..."
cd liboqs

# Clean previous build
if [ -d "build" ]; then
    echo "🧹 Cleaning previous build..."
    rm -rf build
fi

mkdir build
cd build

echo "⚙️ Configuring liboqs build..."
cmake -DCMAKE_INSTALL_PREFIX=../install \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_MINIMAL_BUILD="KEM_kyber_768;SIG_falcon_512" \
      ..

echo "🔨 Compiling liboqs (this may take a few minutes)..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "📦 Installing liboqs..."
make install

cd ../../

echo "✅ liboqs build complete"

# Setup Python environment
echo "🐍 Setting up Python environment..."

if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "🔄 Activating virtual environment..."
source venv/bin/activate

echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
if [ -f "requirements.txt" ]; then
    echo "📥 Installing Python dependencies..."
    pip install -r requirements.txt
else
    echo "📥 Installing core dependencies..."
    pip install fastapi uvicorn cryptography sqlalchemy pydantic bcrypt PyJWT httpx python-multipart websockets
fi

# Install liboqs-python from local source
echo "🔐 Installing liboqs-python bindings..."
cd liboqs-python
pip install -e .
cd ..

# Test liboqs installation
echo "🧪 Testing liboqs installation..."
python3 -c "
import sys
sys.path.insert(0, './liboqs-python')
try:
    import oqs
    print('✅ liboqs imported successfully')
    print(f'✅ Version: {getattr(oqs, \"oqs_version\", lambda: \"Unknown\")()}')
    
    # Test KEM
    if 'Kyber768' in oqs.get_enabled_kem_mechanisms():
        print('✅ ML-KEM-768 (Kyber768) available')
    else:
        print('❌ ML-KEM-768 not available')
        sys.exit(1)
    
    # Test Signature
    if 'Falcon-512' in oqs.get_enabled_sig_mechanisms():
        print('✅ Falcon-512 available') 
    else:
        print('❌ Falcon-512 not available')
        sys.exit(1)
        
    print('🎉 Quantum cryptography ready!')
except ImportError as e:
    print(f'❌ liboqs import failed: {e}')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ liboqs test failed!"
    exit 1
fi

# Setup SSL certificates if mkcert is available
echo "🔒 Checking for SSL certificate support..."
if command -v mkcert &> /dev/null; then
    echo "✅ mkcert found - setting up SSL certificates..."
    mkcert -install 2>/dev/null || true
    
    # Detect local IP
    LOCAL_IP=$(ip route get 1 2>/dev/null | grep -Po 'src \K\S+' 2>/dev/null || \
               route get default 2>/dev/null | grep 'interface:' | awk '{print $2}' | xargs ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1 || \
               echo "localhost")
    
    if [ "$LOCAL_IP" != "localhost" ] && [ -n "$LOCAL_IP" ]; then
        echo "📜 Creating certificates for localhost and $LOCAL_IP"
        mkcert localhost 127.0.0.1 ::1 "$LOCAL_IP"
    else
        echo "📜 Creating certificates for localhost only"
        mkcert localhost 127.0.0.1 ::1
    fi
    
    echo "✅ SSL certificates created"
else
    echo "⚠️  mkcert not found - SSL certificates not created"
    echo "💡 Install mkcert for HTTPS support:"
    if [[ "$OS" == "macOS" ]]; then
        echo "   brew install mkcert"
    else
        echo "   Visit: https://github.com/FiloSottile/mkcert#installation"
    fi
fi

echo
echo "🎉 QMS Platform Setup Complete!"
echo "================================"
echo
echo "📋 What was installed:"
echo "  ✅ liboqs quantum cryptography library"
echo "  ✅ Python virtual environment with all dependencies"
echo "  ✅ liboqs-python bindings"
echo "  ✅ ML-KEM-768 (Kyber768) support"
echo "  ✅ Falcon-512 signature support"
echo
echo "🚀 To start the platform:"
echo "  ./deploy_ssl.sh     (HTTPS - recommended)"
echo "  ./deploy_http.sh    (HTTP - if no mkcert)"
echo
echo "🧪 To test quantum crypto:"
echo "  source venv/bin/activate"
echo "  python3 -c \"import oqs; print('Quantum ready!')\""
echo
echo "✅ Platform ready for quantum-secure messaging!"