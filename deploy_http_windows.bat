@echo off
REM Windows HTTP Deployment Script for QMS Platform (No SSL Required)
REM Starts all services with HTTP (for users without mkcert)

setlocal enabledelayedexpansion

echo 🌐 Starting QMS Platform (HTTP Mode - Windows)
echo ================================================

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

echo ⚠️  Running in HTTP mode (no SSL encryption)
echo 💡 For HTTPS support, install mkcert and use deploy_ssl_windows.bat

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

REM Start Quantum Service (Port 3001) - HTTP mode
echo 🚀 Starting Quantum Crypto Service (HTTP:3001)...
start /b python backend\service.py --no-ssl > quantum_http.log 2>&1
timeout /t 3 >nul

REM Start Main App (Port 4000) - HTTP mode
echo 🚀 Starting QMS Main Application (HTTP:4000)...
start /b python backend\app.py --no-ssl > app_http.log 2>&1
timeout /t 3 >nul

REM Start Frontend (Port 8000) - HTTP mode
echo 🚀 Starting HTTP Frontend Server (HTTP:8000)...
start /b python start_https_server.py --no-ssl > frontend_http.log 2>&1
timeout /t 2 >nul

echo.
echo 🎉 HTTP Deployment Complete!
echo =============================
echo 🌐 Frontend:     http://localhost:8000
echo 🌐 Main App:     http://localhost:4000  
echo 🌐 Quantum API:  http://localhost:3001
echo.

if not "!LOCAL_IP!"=="localhost" (
    echo 🌐 LAN Access (Share with others):
    echo 🌐 Frontend:     http://!LOCAL_IP!:8000
    echo 🌐 Main App:     http://!LOCAL_IP!:4000
    echo 🌐 Quantum API:  http://!LOCAL_IP!:3001
    echo.
    echo 📱 Mobile/Remote Access:
    echo    Share this link: http://!LOCAL_IP!:8000
)

echo.
echo ⚠️  SECURITY NOTE: HTTP mode is not encrypted!
echo 🔒 For secure deployment, install mkcert and use deploy_ssl_windows.bat
echo.
echo 📝 Logs:
echo    type quantum_http.log
echo    type app_http.log
echo    type frontend_http.log
echo.
echo 🔧 Network Info:
echo    Device IP: !LOCAL_IP!
echo    Mode: HTTP (unencrypted)
echo.
echo 🛑 To stop all: taskkill /f /im python.exe
echo.
echo ✅ Platform is now running! Access at http://localhost:8000
pause