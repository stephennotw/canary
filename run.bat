@echo off
REM Canary - Anti-Forensics Detector - One-Click Run Script (Windows)
REM ================================================================

echo.
echo   Canary - Anti-Forensics Detector
echo   =================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate and install dependencies
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -q -r requirements.txt 2>nul

REM Run Canary with all provided arguments, or show help
if "%~1"=="" (
    echo.
    echo Usage: run.bat [OPTIONS]
    echo.
    echo Quick Start:
    echo   run.bat --live                          # Scan live system (admin required)
    echo   run.bat --mft-csv MFT.csv               # Analyze MFT export
    echo   run.bat --evtx-path .\logs\             # Analyze event logs
    echo   run.bat --help                          # Show all options
    echo.
    echo Full example:
    echo   run.bat --mft-csv MFT.csv --usn-csv J.csv --evtx-path .\logs\ --format both
    echo.
    python -m canary --help
) else (
    python -m canary %*
)

pause
