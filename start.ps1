$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker CLI not found. Please install and start Docker Desktop first.'
}

# -- 1. Docker Backend + Sandbox --
$backendImage = docker images -q agentfuzzer-backend:latest
$sandboxImage = docker images -q agentfuzzer-sandbox:latest

if ($backendImage -and $sandboxImage) {
  Write-Host "[OK] Backend/Sandbox images found, starting..."
} else {
  Write-Host "[BUILD] Building Backend + Sandbox images..."
  & docker compose up --build -d backend sandbox
  if ($LASTEXITCODE -ne 0) { throw "Docker compose build failed" }
  Write-Host "[OK] Backend + Sandbox started"
}

if (-not $backendImage -or -not $sandboxImage) {
  # already started above
} else {
  & docker compose up -d backend sandbox
}

# -- 2. Frontend --
$frontendDir = Join-Path $PSScriptRoot "frontend"
$distDir = Join-Path $frontendDir "dist"

if (-not (Test-Path $distDir)) {
  Write-Host "[BUILD] Building Frontend..."
  Push-Location $frontendDir
  npm install
  npm run build
  Pop-Location
}

$serveProc = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
  $_.CommandLine -match "serve.*5173"
}
if (-not $serveProc) {
  Write-Host "[OK] Starting Frontend (npx serve)..."
  Start-Process -FilePath "npx" -ArgumentList "serve",$distDir,"-l","5173","-s" -WindowStyle Hidden
  Start-Sleep -Seconds 3
} else {
  Write-Host "[OK] Frontend already running"
}

# -- 3. Health Check --
Start-Sleep -Seconds 5

try {
  $backend = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/' -Method Get -TimeoutSec 15
  Write-Host "[OK] Backend ready: $($backend.name) v$($backend.version)"
} catch {
  Write-Host "[WARN] Backend is still starting or not reachable yet."
}

try {
  $sandbox = Invoke-RestMethod -Uri 'http://127.0.0.1:18080/health' -Method Get -TimeoutSec 15
  Write-Host "[OK] Sandbox ready: $($sandbox.agent)"
} catch {
  Write-Host "[WARN] Sandbox is still starting or not reachable yet."
}

try {
  $frontend = Invoke-RestMethod -Uri 'http://127.0.0.1:5173/' -Method Get -TimeoutSec 10
  Write-Host "[OK] Frontend ready"
} catch {
  Write-Host "[WARN] Frontend is not reachable yet."
}

try {
  Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/payloads/import-from-yaml' -Method Post -TimeoutSec 30 | Out-Null
  Write-Host "[OK] Built-in payloads imported."
} catch {
  Write-Host "[WARN] Payload import skipped or failed."
}

Write-Host ""
Write-Host "============================================"
Write-Host "Frontend: http://127.0.0.1:5173"
Write-Host "Backend:  http://127.0.0.1:8000"
Write-Host "Docs:     http://127.0.0.1:8000/docs"
Write-Host "Sandbox:  http://127.0.0.1:18080"
Write-Host "============================================"
