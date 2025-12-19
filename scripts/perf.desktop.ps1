$ErrorActionPreference = "Stop"

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
  $baseUrl = "http://localhost:18080"
  # Use a unique salt per test run to avoid CLIENT_DUPLICATE conflicts with the installed Windows service.
  # The service has its own embedded config with a different salt/device ID.
  $salt = "perf_" + (Get-Date -Format "yyyyMMddHHmmss")
  # Position marker in bottom-right corner to avoid browser window overlap.
  $markerX = if ($env:PERF_MARKER_X) { [int]$env:PERF_MARKER_X } else { 3200 }
  $markerY = if ($env:PERF_MARKER_Y) { [int]$env:PERF_MARKER_Y } else { 1200 }
  $durationSec = if ($env:PERF_DURATION_SEC) { [int]$env:PERF_DURATION_SEC } else { 30 }
  $runId = (Get-Date -Format "yyyyMMdd_HHmmss")

  # Stop the Windows service to prevent CLIENT_DUPLICATE (same machine ID).
  # The service and test client share the same hardware-derived device ID.
  $serviceName = "WinUpdateSvc"
  $serviceWasRunning = $false
  $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[Service] Stopping $serviceName to prevent CLIENT_DUPLICATE..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    $serviceWasRunning = $true
    Start-Sleep -Milliseconds 500
  }

  # Also kill any stray client processes that might cause CLIENT_DUPLICATE.
  Get-Process -Name "UpdateService" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

  # Kill any client_perf.* processes from previous runs (timestamped binaries).
  Get-Process | Where-Object { $_.ProcessName -like "client_perf*" -or $_.ProcessName -like "client_base*" } | Stop-Process -Force -ErrorAction SilentlyContinue

  # Ensure no stale perf processes keep binaries/logs locked.
  foreach ($proc in @("perfmarker","server_perf")) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }

  $logsDir = Join-Path (Get-Location) "logs"
  New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

  $serverOut = Join-Path $logsDir "perf_server.$runId.out.log"
  $serverErr = Join-Path $logsDir "perf_server.$runId.err.log"
  $clientOut = Join-Path $logsDir "perf_client.$runId.out.log"
  $clientErr = Join-Path $logsDir "perf_client.$runId.err.log"
  $markerOut = Join-Path $logsDir "perf_marker.$runId.out.log"
  $markerErr = Join-Path $logsDir "perf_marker.$runId.err.log"

  # Ensure no stale instance lock blocks the server.
  $lockPath = Join-Path $env:TEMP "rocket-server.lock"
  if (Test-Path $lockPath) { Remove-Item $lockPath -Force -ErrorAction SilentlyContinue }

  Write-Host "[Build] server + client + perfmarker"
  go build -o .\built\server_perf.exe .\server
  go build -o .\built\client_base_perf.exe .\client
  go build -o .\built\perfmarker.exe .\cmd\perfmarker

  Write-Host "[Start] server"
  $server = Start-Process -FilePath .\built\server_perf.exe -ArgumentList @("-config",".\config.e2e.json") -PassThru -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr
  Write-Host "  server_pid=$($server.Id)"

  $deadline = (Get-Date).AddSeconds(20)
  $serverReady = $false
  while ((Get-Date) -lt $deadline) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "$baseUrl/"
      if ($r.StatusCode -ge 200) { $serverReady = $true; break }
    } catch {}
    Start-Sleep -Milliseconds 200
  }
  if (-not $serverReady) {
    throw "Server did not become ready at $baseUrl within 20s (pid=$($server.Id)). See $serverOut / $serverErr"
  }

  Write-Host "[Build] configured client binary"
  $clientExe = ".\built\client_perf.$runId.exe"
  go run .\gen_config.go -host localhost -port 18080 -secure=false -salt $salt -path / .\built\client_base_perf.exe $clientExe | Out-Null

  Write-Host "[Start] client (--console, disable auto-update)"
  $env:SPARK_DISABLE_UPDATE = "1"
  # Use unique machine ID app name to avoid CLIENT_DUPLICATE conflicts with the installed Windows service.
  $env:SPARK_MACHINE_ID_APP_NAME = "RocketPerf_$runId"
  # Perf harness: keep overlay disabled (it forces CPU readback paths).
  $env:SPARK_PERF_MARKER_OVERLAY = "0"
  # Prefer lowest-latency queueing for WebRTC perf (drop stale frames instead of buffering them).
  $env:SPARK_WEBRTC_FRAME_QUEUE = "1"
  # Prefer direct DXGI -> hardware MFT input when available.
  $env:SPARK_WEBRTC_H264_DXGI = "1"
  # WS tiles require a CPU RGBA capture backend; the default auto backend may select
  # DXGI NV12 (GPU-only) which is intended for WebRTC/video transport.
  if (-not $env:PERF_TRANSPORT) { $env:PERF_TRANSPORT = "webrtc" }
  # Let the client use its default capture backend (DXGI/auto)
  # GDI was causing missed marker updates due to DWM timing issues
  $client = Start-Process -FilePath $clientExe -ArgumentList @("--console") -PassThru -RedirectStandardOutput $clientOut -RedirectStandardError $clientErr
  Write-Host "  client_pid=$($client.Id)"

  # Wait for client to connect to server before proceeding.
  # This prevents race conditions where the test starts before the client is ready.
  Write-Host "[Wait] client connection..."
  $clientDeadline = (Get-Date).AddSeconds(15)
  $clientConnected = $false
  while ((Get-Date) -lt $clientDeadline) {
    try {
      $devicesResp = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "$baseUrl/api/devices"
      if ($devicesResp.StatusCode -eq 200) {
        $devices = $devicesResp.Content | ConvertFrom-Json
        if ($devices.Count -gt 0) {
          $clientConnected = $true
          Write-Host "  client connected (device_count=$($devices.Count))"
          break
        }
      }
    } catch {}
    Start-Sleep -Milliseconds 200
  }
  if (-not $clientConnected) {
    Write-Host "[WARN] Client may not have connected within 15s - continuing anyway"
  }

  Write-Host "[Start] marker window"
  $marker = Start-Process -FilePath .\built\perfmarker.exe -ArgumentList @("--x",$markerX,"--y",$markerY,"--w",200,"--h",200,"--fps",30,"--duration","0s","--marker-pad",8,"--marker-size",24,"--marker-gap",2) -PassThru -RedirectStandardOutput $markerOut -RedirectStandardError $markerErr
  Write-Host "  marker_pid=$($marker.Id)"

  # Parse marker "READY ..." line to get the actual on-screen coords (DPI-aware).
  $readyDeadline = (Get-Date).AddSeconds(5)
  while ((Get-Date) -lt $readyDeadline) {
    if (Test-Path $markerOut) {
      $matchLine = (Select-String -Path $markerOut -Pattern '^READY\\s+x=' -ErrorAction SilentlyContinue | Select-Object -First 1).Line
      $line = if ($matchLine) { $matchLine } else { (Get-Content $markerOut -Tail 1 -ErrorAction SilentlyContinue) }
      if ($line -and $line -match '^READY\\s+x=(\\d+)\\s+y=(\\d+)\\s+w=(\\d+)\\s+h=(\\d+)\\s+fps=(\\d+)\\s+marker_pad=(\\d+)\\s+marker_size=(\\d+)\\s+marker_gap=(\\d+)') {
        $env:PERF_MARKER_X = $Matches[1]
        $env:PERF_MARKER_Y = $Matches[2]
        $env:PERF_MARKER_PAD = $Matches[6]
        $env:PERF_MARKER_SIZE = $Matches[7]
        $env:PERF_MARKER_GAP = $Matches[8]
        Write-Host "  marker_ready x=$($Matches[1]) y=$($Matches[2]) pad=$($Matches[6]) size=$($Matches[7]) gap=$($Matches[8])"
        break
      }
    }
    Start-Sleep -Milliseconds 100
  }

  Write-Host "[Run] Playwright perf test (set PERF_HEADED=1 for headed)"
  Push-Location "web"
  try {
    if (!(Test-Path "node_modules")) { npm install }
    npx playwright install chromium | Out-Null

    $env:ROCKET_HARDWARE_PERF = "1"
    $env:BASE_URL = $baseUrl
    $env:PERF_HEADED = $env:PERF_HEADED  # pass-through
    $env:PERF_DURATION_SEC = "$durationSec"
    $env:PERF_TEST_TIMEOUT_MS = "$([Math]::Max(180000, ($durationSec + 180) * 1000))"
    if (-not $env:PERF_MARKER_X) { $env:PERF_MARKER_X = "$markerX" }
    if (-not $env:PERF_MARKER_Y) { $env:PERF_MARKER_Y = "$markerY" }
    if (-not $env:PERF_TRANSPORT) { $env:PERF_TRANSPORT = "webrtc" }

    npx playwright test -c playwright.perf.config.js
  } finally {
    Pop-Location
  }
} finally {
  Write-Host "[Cleanup]"
  foreach ($proc in @("perfmarker","client_perf","server_perf")) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  # Restart the Windows service if it was running before the test.
  if ($serviceWasRunning) {
    Write-Host "[Service] Restarting $serviceName..."
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
  }
  Pop-Location
}
