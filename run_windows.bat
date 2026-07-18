@echo off
REM ============================================================
REM  RedShell Advanced Framework - Windows Launcher
REM ============================================================
setlocal enabledelayedexpansion
title RedShell Advanced Framework

echo ============================================================
echo   RedShell Advanced Framework - Starting Up
echo ============================================================
echo.

REM --- Check Python is installed ---
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found on PATH.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo and make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM --- Create virtual environment if it doesn't exist ---
if not exist "venv\" (
    echo [SETUP] Creating virtual environment...
    python -m venv venv
)

REM --- Activate virtual environment ---
call venv\Scripts\activate.bat

REM --- Install dependencies ---
echo [SETUP] Installing/checking dependencies...
pip install -q --disable-pip-version-check -r backend\requirements.txt
pip install -q --disable-pip-version-check flask

REM --- Check for .env file with API key ---
if not exist ".env" (
    echo.
    echo [INFO] No .env file found. AI Analyst will run in rule-based fallback mode.
    echo [INFO] To enable full AI analysis, create a .env file with:
    echo        ANTHROPIC_API_KEY=your_key_here
    echo.
) else (
    echo [SETUP] Loading environment variables from .env...
    for /f "usebackq tokens=1,2 delims==" %%a in (".env") do (
        if not "%%a"=="" set %%a=%%b
    )
)

REM --- Start the demo vulnerable target in a new window ---
echo [START] Launching demo target on http://localhost:5050 ...
start "RedShell Demo Target" cmd /c "call venv\Scripts\activate.bat && python demo_target\vulnerable_app.py"

REM --- Give it a moment to start ---
timeout /t 2 /nobreak >nul

REM --- Start the main RedShell backend ---
echo [START] Launching RedShell dashboard on http://localhost:8000 ...
echo.
echo ============================================================
echo   Dashboard:    http://localhost:8000
echo   Demo target:  http://localhost:5050
echo   Press CTRL+C in this window to stop RedShell.
echo ============================================================
echo.

REM --- Open the browser automatically ---
start http://localhost:8000

cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000

pause
