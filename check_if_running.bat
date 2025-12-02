@echo off
echo ============================================
echo   Checking for Port Killer in background...
echo ============================================
echo.
tasklist | findstr /i "python"
echo.
echo ============================================
echo If you see port_killer.py above, it's running.
echo If you see nothing, it's NOT running.
echo ============================================
echo.
pause
