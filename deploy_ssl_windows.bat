@echo off
REM Windows SSL Deployment Script for QMS Platform
REM Starts all services with HTTPS encryption

setlocal enabledelayedexpansion

echo 🔒 Starting QMS Platform with SSL Encryption (Windows)
echo =======================================================

REM Get the script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo 📁 Working Directory: %SCRIPT_DIR%

REM Detect local IP address
echo 🌐 Detecting network configuration...
set "LOCAL_IP="

REM Try to get IP address from ipconfig
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /i "IPv4"') do (
    for /f "tokens=1" %%j in ("%%i") do (
        set "TEMP_IP=%%j"
        REM Remove leading spaces
        set "TEMP_IP=!TEMP_IP: =!"
        REM Check if it's not localhost
        if not "!TEMP_IP!"=="127.0.0.1" (
            if not defined LOCAL_IP (
                set "LOCAL_IP=!TEMP_IP!"
            )
        )
    )
)

if defined LOCAL_IP (
    echo ✅ Detected Local IP: !LOCAL_IP!
) else (
    echo ⚠️  Could not detect local IP - using localhost only
    set "LOCAL_IP=localhost"
)

REM Kill existing processes
echo 🛑 Stopping existing services...
taskkill /f /im python.exe 2>nul >nul
timeout /t 2 >nul

REM Check for SSL certificates
if not exist "localhost+3.pem" (
    echo ❌ SSL certificates not found!
    echo 🔒 Creating certificates with mkcert...
    
    where mkcert >nul 2>nul
    if errorlevel 1 (
        echo ❌ mkcert not found! Please install mkcert for SSL support
        echo    Windows: choco install mkcert  OR  scoop install mkcert
        echo    Then run: mkcert -install
        pause
        exit /b 1
    )
    
    if not "!LOCAL_IP!"=="localhost" (
        echo 📜 Generating certificates for localhost, 127.0.0.1, and !LOCAL_IP!
        mkcert localhost 127.0.0.1 ::1 !LOCAL_IP!
    ) else (
        echo 📜 Generating certificates for localhost only
        mkcert localhost 127.0.0.1 ::1
    )
)

echo ✅ SSL certificates verified

REM Check if Python is available
python --version >nul 2>nul
if errorlevel 1 (
    echo ❌ Python not found! Please install Python 3.8+ and add to PATH
    pause
    exit /b 1
)

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo 🐍 Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo ⚠️  Virtual environment not found - using system Python
)

REM Start Quantum Service (Port 3001)
echo 🚀 Starting Quantum Crypto Service (HTTPS:3001)...
start /b python backend\service.py > quantum_ssl.log 2>&1
timeout /t 3 >nul

REM Start Main App (Port 4000)  
echo 🚀 Starting QMS Main Application (HTTPS:4000)...
start /b python backend\app.py > app_ssl.log 2>&1
timeout /t 3 >nul

REM Start Frontend (Port 8000)
echo 🚀 Starting HTTPS Frontend Server (HTTPS:8000)...
start /b python start_https_server.py > frontend_ssl.log 2>&1
timeout /t 2 >nul

echo.
echo 🎉 SSL Deployment Complete!
echo ==========================
echo 🔒 Frontend:     https://localhost:8000
echo 🔒 Main App:     https://localhost:4000
echo 🔒 Quantum API:  https://localhost:3001
echo.

if not "!LOCAL_IP!"=="localhost" (
    echo 🌐 LAN Access (Share with others):
    echo 🔒 Frontend:     https://!LOCAL_IP!:8000
    echo 🔒 Main App:     https://!LOCAL_IP!:4000
    echo 🔒 Quantum API:  https://!LOCAL_IP!:3001
    echo.
    echo 📱 Mobile/Remote Access:
    echo    Share this link: https://!LOCAL_IP!:8000
) else (
    echo ⚠️  LAN access not available - local IP detection failed
    echo 💡 Manual setup: Create certificates with your IP using mkcert
)

echo.
echo 📝 Logs:
echo    type quantum_ssl.log
echo    type app_ssl.log  
echo    type frontend_ssl.log
echo.
echo 🔧 Network Info:
echo    Device IP: !LOCAL_IP!
echo.
echo 🛑 To stop all: taskkill /f /im python.exe
echo.
echo ✅ Platform is now running! Access at https://localhost:8000
pause