@echo off
REM Complete Windows Setup Script for QMS Platform with liboqs
REM Builds and installs liboqs quantum cryptography library

setlocal enabledelayedexpansion

echo 🔐 QMS Platform Complete Setup with Quantum Cryptography (Windows)
echo ================================================================

REM Check for required tools
echo 📋 Checking dependencies...

python --version >nul 2>nul
if errorlevel 1 (
    echo ❌ Python not found!
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

cmake --version >nul 2>nul
if errorlevel 1 (
    echo ❌ CMake not found!
    echo Please install CMake from https://cmake.org/download/
    echo Or use: winget install Kitware.CMake
    pause
    exit /b 1
)

where /q git
if errorlevel 1 (
    echo ❌ Git not found!
    echo Please install Git from https://git-scm.com/
    pause
    exit /b 1
)

echo ✅ All dependencies found

REM Check for Visual Studio Build Tools
echo 🔨 Checking for C++ build tools...
where /q cl >nul 2>nul
if errorlevel 1 (
    echo ⚠️  Visual Studio Build Tools not found
    echo Please install one of:
    echo   1. Visual Studio 2019/2022 with C++ workload
    echo   2. Visual Studio Build Tools 2019/2022
    echo   3. winget install Microsoft.VisualStudio.2022.BuildTools
    echo.
    set /p "continue=Continue anyway? (y/N): "
    if /i "!continue!" neq "y" (
        pause
        exit /b 1
    )
)

REM Build liboqs
echo 🔨 Building liboqs quantum cryptography library...
cd liboqs

REM Clean previous build
if exist "build" (
    echo 🧹 Cleaning previous build...
    rmdir /s /q build
)

mkdir build
cd build

echo ⚙️ Configuring liboqs build for Windows...
cmake -G "Visual Studio 16 2019" ^
      -DCMAKE_INSTALL_PREFIX=../install ^
      -DBUILD_SHARED_LIBS=ON ^
      -DOQS_BUILD_ONLY_LIB=ON ^
      -DOQS_MINIMAL_BUILD="KEM_kyber_768;SIG_falcon_512" ^
      ..

if errorlevel 1 (
    echo ❌ CMake configuration failed!
    echo Trying alternative generator...
    cmake -G "NMake Makefiles" ^
          -DCMAKE_INSTALL_PREFIX=../install ^
          -DBUILD_SHARED_LIBS=ON ^
          -DOQS_BUILD_ONLY_LIB=ON ^
          -DOQS_MINIMAL_BUILD="KEM_kyber_768;SIG_falcon_512" ^
          ..
    
    if errorlevel 1 (
        echo ❌ CMake configuration failed with all generators!
        pause
        exit /b 1
    )
    
    echo 🔨 Building with NMake...
    nmake
    nmake install
) else (
    echo 🔨 Building with Visual Studio...
    cmake --build . --config Release --target install
)

cd ..\..\

if not exist "liboqs\install" (
    echo ❌ liboqs build failed!
    pause
    exit /b 1
)

echo ✅ liboqs build complete

REM Setup Python environment
echo 🐍 Setting up Python environment...

if not exist "venv" (
    echo 📦 Creating Python virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
)

echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

echo ⬆️ Upgrading pip...
python -m pip install --upgrade pip

REM Install Python dependencies
if exist "requirements.txt" (
    echo 📥 Installing Python dependencies...
    pip install -r requirements.txt
) else (
    echo 📥 Installing core dependencies...
    pip install fastapi uvicorn cryptography sqlalchemy pydantic bcrypt PyJWT httpx python-multipart websockets
)

REM Install liboqs-python from local source
echo 🔐 Installing liboqs-python bindings...
cd liboqs-python

REM Set environment variables for Windows build
set "CMAKE_PREFIX_PATH=%~dp0liboqs\install"
set "PKG_CONFIG_PATH=%~dp0liboqs\install\lib\pkgconfig"

pip install -e .
cd ..

if errorlevel 1 (
    echo ❌ liboqs-python installation failed!
    echo Try: pip install liboqs-python
    pause
    exit /b 1
)

REM Test liboqs installation
echo 🧪 Testing liboqs installation...
python -c "import sys; sys.path.insert(0, './liboqs-python'); import oqs; print('✅ liboqs ready'); print('✅ Kyber768:', 'Kyber768' in oqs.get_enabled_kem_mechanisms()); print('✅ Falcon-512:', 'Falcon-512' in oqs.get_enabled_sig_mechanisms())"

if errorlevel 1 (
    echo ❌ liboqs test failed!
    pause
    exit /b 1
)

REM Setup SSL certificates if mkcert is available
echo 🔒 Checking for SSL certificate support...
where mkcert >nul 2>nul
if not errorlevel 1 (
    echo ✅ mkcert found - setting up SSL certificates...
    mkcert -install >nul 2>nul
    
    REM Detect local IP
    for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr "IPv4"') do (
        set "LOCAL_IP=%%i"
        set "LOCAL_IP=!LOCAL_IP: =!"
        goto :ip_found
    )
    set "LOCAL_IP=localhost"
    
    :ip_found
    if not "!LOCAL_IP!"=="localhost" (
        echo 📜 Creating certificates for localhost and !LOCAL_IP!
        mkcert localhost 127.0.0.1 ::1 !LOCAL_IP!
    ) else (
        echo 📜 Creating certificates for localhost only
        mkcert localhost 127.0.0.1 ::1
    )
    
    echo ✅ SSL certificates created
) else (
    echo ⚠️  mkcert not found - SSL certificates not created
    echo 💡 Install mkcert for HTTPS support:
    echo    choco install mkcert   (with Chocolatey)
    echo    scoop install mkcert   (with Scoop)
)

echo.
echo 🎉 QMS Platform Setup Complete!
echo ================================
echo.
echo 📋 What was installed:
echo   ✅ liboqs quantum cryptography library
echo   ✅ Python virtual environment with all dependencies
echo   ✅ liboqs-python bindings
echo   ✅ ML-KEM-768 (Kyber768) support
echo   ✅ Falcon-512 signature support
echo.
echo 🚀 To start the platform:
echo   .\deploy_ssl_windows.bat     (HTTPS - recommended)
echo   .\deploy_http_windows.bat    (HTTP - if no mkcert)
echo.
echo 🧪 To test quantum crypto:
echo   venv\Scripts\activate
echo   python -c "import oqs; print('Quantum ready!')"
echo.
echo ✅ Platform ready for quantum-secure messaging!
pause