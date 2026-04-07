<#
.SYNOPSIS
    NTF Initial Hardening Script - Active Directory & DNS
.DESCRIPTION
    Automates rapid triage, network containment, and evidence gathering.
    Explicitly disables Real-Time Protection for Grey Team compliance while 
    leveraging Windows Defender Firewall for strict network isolation.
#>

$IR_Path = "C:\IR"
$LogFile = "$IR_Path\hardening_errors.txt"
$ScriptDir = $PSScriptRoot

Clear-Host
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " NINE-TAILED FOX: INITIAL HARDENING SCRIPT       " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Function Write-Status ($Message, $Color = "Green") { Write-Host "[*] $Message" -ForegroundColor $Color }
Function Log-Error ($Action, $Exception) {
    Write-Host "[!] ERROR during $Action. See log." -ForegroundColor Red
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Action - $($Exception.Message)" | Out-File -FilePath $LogFile -Append
}

# --- 1. Establish IR Environment ---
Try {
    If (!(Test-Path $IR_Path)) { New-Item -ItemType Directory -Path $IR_Path -Force | Out-Null }
    
    If (!(Test-Path "$IR_Path\autorunsc.exe")) {
        If (Test-Path "$ScriptDir\sysinternals_tools.zip") {
            Expand-Archive -Path "$ScriptDir\sysinternals_tools.zip" -DestinationPath $IR_Path -Force
            Write-Status "Extracted Sysinternals Tools to $IR_Path" "Yellow"
        } Else { Write-Host "[!] Warning: sysinternals_tools.zip not found." -ForegroundColor Red }
    } Else { Write-Status "Sysinternals tools ready." }
} Catch { Log-Error "IR Environment Setup" $_ }

# --- 2. Defender Compliance & Firewall Enforcement ---
Try {
    # Comply with Grey Team: Disable AV Real-Time Protection
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Write-Status "Grey Team Compliance: Real-Time Protection Disabled." "Yellow"

    # Enforce Defender Firewall on all profiles (Domain, Private, Public)
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Status "Windows Defender Firewall is ENABLED across all profiles." "Yellow"
} Catch { Log-Error "Defender Compliance" $_ }

# --- 3. Verify Containment Programming (Scored Services) ---
Try {
    $CriticalServices = @("NTDS", "DNS", "Netlogon")
    Foreach ($Service in $CriticalServices) {
        $SvcStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue
        If ($null -eq $SvcStatus) { Continue }
        
        If ($SvcStatus.Status -ne "Running") {
            Start-Service -Name $Service -ErrorAction Stop
            Write-Status "Service $Service was down and has been restarted." "Yellow"
        } Else { Write-Status "Service $Service is Running." }
    }
} Catch { Log-Error "Service Verification" $_ }

# --- 4. Automated Port Hardening (Rule #8 Compliant) ---
Try {
    $RuleName = "NTF_Block_C2"
    If (!(Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -Protocol TCP -LocalPort 4444,8080,1337,44444 -ErrorAction Stop | Out-Null
        Write-Status "Defender Firewall: C2 Port blocking rule established." "Yellow"
    } Else { Write-Status "Defender Firewall: C2 Port blocking rule active." }
} Catch { Log-Error "Port Hardening" $_ }

# --- 5. Automated SMB Hardening ---
Try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Status "SMBv1 Disabled and SMB Signing Required." "Yellow"
} Catch { Log-Error "SMB Hardening" $_ }

# --- 6. Automated Persistence Hunt (Autoruns) ---
Try {
    If (Test-Path "$IR_Path\autorunsc.exe") {
        If (!(Test-Path "$IR_Path\persistence.csv")) {
            Write-Status "Running Autoruns... this may take a few seconds." "Yellow"
            Start-Process -FilePath "$IR_Path\autorunsc.exe" -ArgumentList "-a * -c -m -accepteula" -RedirectStandardOutput "$IR_Path\persistence.csv" -Wait
            Write-Status "Persistence CSV generated at $IR_Path\persistence.csv" "Yellow"
        } Else { Write-Status "Persistence CSV already exists. Skipping." }
    }
} Catch { Log-Error "Persistence Hunt" $_ }

# --- 7. Start Packet Capture (Rule #5 Compliant) ---
Try {
    If ((pktmon status) -match "Running") {
        Write-Status "Pktmon is already actively capturing traffic."
    } Else {
        pktmon filter add -p 4444 8080 1337 | Out-Null
        pktmon start --etw -f $IR_Path\capture.etl | Out-Null
        Write-Status "Packet capture initiated at $IR_Path\capture.etl" "Yellow"
    }
} Catch { Log-Error "Packet Capture" $_ }

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " HARDENING COMPLETE. BEGIN HUMAN ANALYSIS.       " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
