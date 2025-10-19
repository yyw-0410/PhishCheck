# ==========================================
# run_backend.ps1
# ==========================================
# FastAPI launcher that auto-deactivates on Ctrl +C
# ==========================================

Write-Host "Setting execution policy temporarily..."
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

Write-Host "Activating virtual environment..."
& "$PSScriptRoot\venv\Scripts\Activate.ps1"

try {
    Write-Host "Environment activated. Starting FastAPI..."
    # Run FastAPI; keep it running until you press Ctrl +C
    python -m uvicorn main:app --reload --port 8000
}
finally {
    Write-Host ""
    Write-Host "Server stopped. Deactivating environment..."

    if (Get-Command deactivate -ErrorAction SilentlyContinue) {
        deactivate
        Write-Host "Environment deactivated."
    }
    else {
        Write-Host "No virtual environment active or deactivate command not found."
    }

    Write-Host ""
    Write-Host "Press Enter to exit..."
    Read-Host
}
