@echo off
chcp 65001 >nul
set PYTHONUTF8=1
title IP Split Audit

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.8+ not found. Please install from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Starting IP Split Audit...
echo.
python "%~dp0ip_split_audit.py" --open %*
echo.
pause
