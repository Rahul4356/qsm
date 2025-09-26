@echo off
REM Windows Setup Script for QMS Platform
REM Sets up Python environment and dependencies

setlocal enabledelayedexpansion

echo 🚀 QMS Platform Setup (Windows)
echo ==================================

REM Check if Python is installed
python --version >nul 2>nul
if errorlevel 1 (
    echo ❌ Python not found!
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo ✅ Python detected: 
python --version

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
) else (
    echo ✅ Virtual environment already exists
)

REM Activate virtual environment
echo 🐍 Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo ⬆️  Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
if exist "requirements.txt" (
    echo 📥 Installing Python dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ❌ Failed to install some dependencies
        echo 💡 Try running as Administrator or check your internet connection
    ) else (
        echo ✅ Dependencies installed successfully
    )
) else (
    echo ⚠️  requirements.txt not found, installing basic dependencies...
    pip install fastapi uvicorn cryptography sqlalchemy pydantic bcrypt PyJWT httpx python-multipart websockets
)

REM Check if mkcert is available
echo 🔒 Checking SSL certificate support...
where mkcert >nul 2>nul
if errorlevel 1 (
    echo ⚠️  mkcert not found
    echo 💡 Install mkcert for SSL support:
    echo    Option 1: choco install mkcert  (if you have Chocolatey)
    echo    Option 2: scoop install mkcert   (if you have Scoop)  
    echo    Option 3: Download from https://github.com/FiloSottile/mkcert/releases
    echo.
    echo After installing mkcert, run: mkcert -install
) else (
    echo ✅ mkcert detected
    mkcert -install 2>nul
    echo ✅ SSL root certificate installed
)

echo.
echo 🎉 Setup Complete!
echo ==================
echo.
echo 🚀 To start the platform:
echo    deploy_ssl_windows.bat
echo.
echo 🌐 Or start services individually:
echo    venv\Scripts\activate
echo    python backend\service.py    (Quantum API)
echo    python backend\app.py        (Main App)
echo    python start_https_server.py (Frontend)
echo.
echo 📋 Default URLs:
echo    Frontend: https://localhost:8000
echo    Main App: https://localhost:4000  
echo    API: https://localhost:3001
echo.
echo ✅ Ready for deployment!
pause