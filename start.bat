@echo off
cd /d %~dp0
cls

echo.
echo  ================================================
echo    ____  _     _     _      ____ _               _
echo   ^|  _ \^| ^|__ ^(_)___^| ^|__  / ___^| ^|__   ___  ___^| ^| __
echo   ^| ^|_) ^| '_ \^| / __^| '_ \^| ^|   ^| '_ \ / _ \/ __^| ^|/ /
echo   ^|  __/^| ^| ^| ^| \__ \ ^| ^| ^| ^|___^| ^| ^| ^|  __/ (__^|   ^<
echo   ^|_^|   ^|_^| ^|_^|_^|___/_^| ^|_^|\____^|_^| ^|_^|\___^|\___^|_^|\_\
echo  ================================================
echo.

:: Install/update backend dependencies (for SQLite support)
echo  [1/3] Checking Backend Dependencies...
cd /d %~dp0backend
pip install -q -r requirements.txt >nul 2>&1
cd /d %~dp0

:: Start Backend in new CMD window with logs
echo  [2/3] Starting Backend Server...
start "PhishCheck Backend" cmd /c "cd /d %~dp0backend && python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
timeout /t 2 /nobreak >nul

:: Start Frontend in new CMD window with logs
echo  [3/3] Starting Frontend Dev Server...
start "PhishCheck Frontend" cmd /c "cd /d %~dp0frontend && npm run dev"
timeout /t 3 /nobreak >nul

echo.
echo  ============================================
echo    Servers running:
echo.
echo    Backend:   http://localhost:8000
echo    Frontend:  http://localhost:5173
echo    Database:  backend/phishcheck.db (SQLite)
echo  ============================================
echo.
echo    Press any key to STOP all servers...
echo.
pause >nul

:: Shutdown
cls
echo.
echo  Shutting down servers...
taskkill /f /im node.exe >nul 2>&1
taskkill /f /im python.exe >nul 2>&1
echo.
echo  Done. Goodbye!
echo.
timeout /t 2 /nobreak >nul