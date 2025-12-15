$ErrorActionPreference = "Stop"

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
  if ($env:OS -eq "Windows_NT") {
    Write-Host "[Capture] Smoke test capture backends"
    go run .\\scripts\\smoke_capture_paths_windows.go
    if ($LASTEXITCODE -ne 0) { throw "Capture smoke test failed ($LASTEXITCODE)" }
  }

  Write-Host "[Go] go test ./..."
  go test ./...
  if ($LASTEXITCODE -ne 0) { throw "go test failed ($LASTEXITCODE)" }

  Write-Host "[Go] go test -tags mockserver ./..."
  go test -tags mockserver ./...
  if ($LASTEXITCODE -ne 0) { throw "go test (mockserver) failed ($LASTEXITCODE)" }

  Write-Host "[Web] Playwright E2E"
  Push-Location "web"
  try {
    if (!(Test-Path "node_modules")) {
      npm install
      if ($LASTEXITCODE -ne 0) { throw "npm install failed ($LASTEXITCODE)" }
    }
    npx playwright install chromium
    if ($LASTEXITCODE -ne 0) { throw "playwright install failed ($LASTEXITCODE)" }
    npx playwright test
    if ($LASTEXITCODE -ne 0) { throw "playwright test failed ($LASTEXITCODE)" }
  } finally {
    Pop-Location
  }
} finally {
  Pop-Location
}
