@echo off
echo Starting CCEA Optimizer...

echo Starting Backend on port 8000...
start "CCEA Backend (FastAPI)" cmd /k "cd /d ""%~dp0backend"" && python -m uvicorn main:app --reload --port 8000"

echo Starting Frontend on port 5500...
start "CCEA Frontend (HTTP Server)" cmd /k "cd /d ""%~dp0frontend"" && python -m http.server 5500"

echo Opening browser...
timeout /t 2 >nul
start http://localhost:5500

echo Application started! Close the respective console windows to stop the servers.

