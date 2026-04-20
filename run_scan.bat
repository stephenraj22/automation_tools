@echo off
REM Security Automation Orchestrator - Simple Command Wrapper
REM Usage: run_scan.bat <domain>

if "%1"=="" (
    echo Usage: run_scan.bat ^<domain^>
    echo Example: run_scan.bat example.com
    exit /b 1
)

python orchestrator.py %1
