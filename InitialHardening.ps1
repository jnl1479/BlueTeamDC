<#
.SYNOPSIS
    First 5 Minutes Hardening Script - Active Directory & DNS
.DESCRIPTION
    Automates the rapid hardening, containment, and evidence gathering for the 
    Nine-Tailed Fox team. Designed to be idempotent.
#>

# --- Configuration & Helper Functions ---
$IR_Path = "C:\IR"
$LogFile = "$IR_Path\ir_errors.txt"
$ScriptDir = $PSScriptRoot

# Clean terminal for clear output
Clear-Host
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " NINE-TAILED FOX: FIRST 5 MINUTES HARDENING SCRIPT  " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Function Write-Status ($Message, $Color = "Green") {
    Write-Host "[*] $Message" -ForegroundColor $Color
}

Function Log-Error ($Action, $Exception) {
    Write-Host "[!] ERROR during $Action. See log." -ForegroundColor Red
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp - $Action - $($Exception.Message)" | Out-File -FilePath $LogFile -Append
}

# --- 1. Establish IR Environment ---
Try {
    If (!(Test-Path $IR_Path)) {
        New-Item -ItemType Directory -Path $IR_Path -Force | Out-Null
        Write-Status "Created IR Directory at $IR_Path" "Yellow"
    } Else {
        Write-Status "IR Directory already exists."
    }

    # Unzip Sysinternals if it hasn't been done yet
    If (!(Test-Path "$IR_Path\autorunsc.exe")) {
        If (Test-Path "$ScriptDir\Sysinternals.zip") {
            Expand-Archive -Path "$ScriptDir\Sysinternals.zip" -DestinationPath $IR_Path -Force
            Write-Status "Extracted Sysinternals to $IR_Path" "Yellow"
        } Else {
            Write-Host "[!] Warning: Sysinternals.zip not found in $ScriptDir" -ForegroundColor Red
        }
    } Else {
        Write-Status "Sysinternals already extracted."
    }
} Catch { Log-Error "IR Environment Setup" $_ }

# --- 2. Verify Containment Programming (Scored Services) ---
Try {
    $CriticalServices = @("NTDS", "DNS", "Netlogon")
    Foreach ($Service in $CriticalServices) {
        $SvcStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue
        If ($null -eq $SvcStatus) {
            Write-Host "[!] WARNING: Service $Service does not exist!" -ForegroundColor Red
            Continue
        }
        
        If ($SvcStatus.Status -ne "Running") {
            Start-Service -Name $Service -ErrorAction Stop
            Write-Status "Service $Service was down and has been restarted." "Yellow"
        } Else {
            Write-Status "Service $Service is Running."
        }
    }
} Catch { Log-Error "Service Verification" $_ }

# --- 3. Automated Port Hardening (Rule #8 Compliant) ---
Try {
    $RuleName = "Block_C2"
    $RuleExists = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    
    If (!$RuleExists) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -Protocol TCP -LocalPort 4444,8080,1337,44444 -ErrorAction Stop | Out-Null
        Write-Status "C2 Port blocking rule established." "Yellow"
    } Else {
        Write-Status "C2 Port blocking rule already active."
    }
} Catch { Log-Error "Port Hardening" $_ }

# --- 4. Automated SMB Hardening ---
Try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Status "SMBv1 Disabled and SMB Signing Required." "Yellow"
} Catch { Log-Error "SMB Hardening" $_ }

# --- 5. Automated Persistence Hunt (Autoruns) ---
Try {
    If (Test-Path "$IR_Path\autorunsc.exe") {
        If (!(Test-Path "$IR_Path\persistence.csv")) {
            Write-Status "Running Autoruns... this may take a few seconds." "Yellow"
            Start-Process -FilePath "$IR_Path\autorunsc.exe" -ArgumentList "-a * -c -accepteula" -RedirectStandardOutput "$IR_Path\persistence.csv" -Wait
            Write-Status "Persistence CSV generated at $IR_Path\persistence.csv" "Yellow"
        } Else {
            Write-Status "Persistence CSV already exists. Skipping to avoid overwrite."
        }
    }
} Catch { Log-Error "Persistence Hunt" $_ }

# --- 6. Start Packet Capture (Rule #5 Compliant) ---
Try {
    # Check if a capture is already running to maintain idempotency
    $PktmonStatus = pktmon status
    If ($PktmonStatus -match "Running") {
        Write-Status "Pktmon is already actively capturing traffic."
    } Else {
        # Filter for known bad ports, then start the capture
        pktmon filter add -p 4444 8080 1337 | Out-Null
        pktmon start --etw -f $IR_Path\capture.etl | Out-Null
        Write-Status "Packet capture initiated at $IR_Path\capture.etl" "Yellow"
    }
} Catch { Log-Error "Packet Capture" $_ }

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " HARDENING COMPLETE. BEGIN HUMAN ANALYSIS.          " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
