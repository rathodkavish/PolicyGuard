@echo off
title PolicyGuard — Continuous Compliance Platform
echo ======================================================================
echo    PolicyGuard: Policy-to-Control Continuous Compliance Platform
echo ======================================================================
echo.
echo  Starting server at http://127.0.0.1:8000 ...
echo  Dashboard UI: http://127.0.0.1:8000
echo.
echo  Press Ctrl+C to terminate the server.
echo ======================================================================
echo.
python -m uvicorn app.main:app --reload --port 8000
pause
