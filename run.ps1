# CCEA Optimizer Startup Script
Write-Host "Starting CCEA Optimizer..." -ForegroundColor Cyan

$root = $PSScriptRoot

# Start backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\backend'; python -m uvicorn main:app --reload --port 8000"

# Start frontend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; python -m http.server 5500"

Start-Sleep -Seconds 2
Start-Process "http://localhost:5500"

Write-Host "Application started at http://localhost:5500" -ForegroundColor Green

