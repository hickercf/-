$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker CLI not found.'
}

& docker compose down

'All compose services stopped.'
