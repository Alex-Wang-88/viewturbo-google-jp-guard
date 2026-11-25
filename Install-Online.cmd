@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fetch-Engine.ps1"
if errorlevel 1 exit /b %ERRORLEVEL%
call "%~dp0Guard.cmd" Install
exit /b %ERRORLEVEL%
