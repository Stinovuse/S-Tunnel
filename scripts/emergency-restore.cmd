@echo off
chcp 65001 >nul
rem S Tunnel: emergency internet restore. Run as administrator.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0emergency-restore.ps1"
pause
