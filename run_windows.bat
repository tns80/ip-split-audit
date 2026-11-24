@echo off
chcp 65001 >nul
title IP Split Audit - 代理分流一键体检工具

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+ (https://www.python.org/downloads/)
    echo 安装时请勾选 "Add Python to PATH"
    pause
    exit /b 1
)

echo 正在启动代理分流一键体检，完成后将自动打开网页版可视化报告...
echo.
python "%~dp0ip_split_audit.py" --open %*
echo.
pause
