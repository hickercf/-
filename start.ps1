$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker CLI not found. Please install and start Docker Desktop first.'
}

& docker compose up --build -d

Start-Sleep -Seconds 8

try {
  $backend = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/' -Method Get -TimeoutSec 15
  "Backend ready: $($backend.name) v$($backend.version)"
} catch {
  'Backend is still starting or not reachable yet.'
}

try {
  $sandbox = Invoke-RestMethod -Uri 'http://127.0.0.1:18080/health' -Method Get -TimeoutSec 15
  "Sandbox ready: $($sandbox.agent)"
} catch {
  'Sandbox is still starting or not reachable yet.'
}

try {
  Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/payloads/import-from-yaml' -Method Post -TimeoutSec 30 | Out-Null
  'Built-in payloads imported.'
} catch {
  'Payload import skipped or failed. You can retry later.'
}

"Frontend: http://127.0.0.1:5173"
"Backend:  http://127.0.0.1:8000"
"Docs:     http://127.0.0.1:8000/docs"
"Sandbox:  http://127.0.0.1:18080"
