@echo off
chcp 65001 >nul
title EEA Unlock
if not exist "%~dp0EEA-Unlock.ps1" (
  echo EEA-Unlock.ps1 not found next to this file.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0EEA-Unlock.ps1"
