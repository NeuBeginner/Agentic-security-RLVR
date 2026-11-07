@echo off
setlocal
chcp 65001 >nul
title AEGIS-RLVR - Read Only Trajectory Audit

set "PROJECT_DIR=%~dp0"
set "APP_FILE=%PROJECT_DIR%modal_app.py"

echo.
echo ==========================================
echo   AEGIS-RLVR - TRAJECTORY AUDIT
echo ==========================================
echo Project: %PROJECT_DIR%
echo.

if not exist "%APP_FILE%" (
    echo ERROR: modal_app.py not found.
    echo Put this BAT file next to modal_app.py.
    pause
    exit /b 1
)

where modal >nul 2>&1
if errorlevel 1 (
    echo ERROR: Modal CLI not found in PATH.
    echo Activate the Python environment with Modal installed.
    pause
    exit /b 2
)

cd /d "%PROJECT_DIR%"

echo Starting read-only trajectory audit...
echo.
echo No GRPO training will be started.
echo No checkpoint save or overwrite is called by this audit branch.
echo No trajectory files are modified by the audit function.
echo.

modal run modal_app.py --mode audit-trajectories

set "RC=%ERRORLEVEL%"

echo.
echo ==========================================
if "%RC%"=="0" (
    echo AUDIT COMMAND FINISHED
) else (
    echo AUDIT FAILED. Exit code: %RC%
)
echo ==========================================
echo.

pause
exit /b %RC%