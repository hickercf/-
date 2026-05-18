$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker CLI not found. Please install and start Docker Desktop first.'
}

# 检查本地是否已有镜像，有则直接启动（避免网络问题导致构建失败）
$backendImage = docker images -q agentfuzzer-backend:latest
$frontendImage = docker images -q agentfuzzer-frontend:latest
$sandboxImage = docker images -q agentfuzzer-sandbox:latest

if ($backendImage -and $frontendImage -and $sandboxImage) {
  "本地镜像已存在，直接启动..."
  & docker compose up -d
} else {
  "本地镜像不存在，尝试构建..."
  & docker compose up --build -d
}

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
