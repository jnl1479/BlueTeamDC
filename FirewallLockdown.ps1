Write-Host "=== INITIATING COMPLIANT FIREWALL LOCKDOWN ===" -ForegroundColor Cyan

# 1. Management IP Whitelisting (Judge-Safe Method)
$AuthorizedIPs = @("10.10.10.41-10.10.10.44", "10.10.10.205", "10.10.10.210")

Write-Host "Nuking any existing RDP/SSH rules created by Red Team..." -ForegroundColor Yellow
# This finds any firewall rule using port 22 or 3389 and deletes it
Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -eq '22' -or $_.LocalPort -eq '3389' } | Get-NetFirewallRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host "Creating strict Allow-list for Blue and Grey Team RDP/SSH..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "BLUE TEAM ALLOW - Admin Access (RDP/SSH)" `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort @(22, 3389) `
                    -RemoteAddress $AuthorizedIPs `
                    -ErrorAction SilentlyContinue | Out-Null

# 2. The Ban-Hammer: Explicitly block inbound dangerous/unnecessary ports
$BlockedPorts = @(
    20, 21, # FTP
    23,     # Telnet
    69,     # TFTP
    80,     # HTTP
    139,    # NetBIOS Session Service
    161,162,# SNMP
    443,    # HTTPS
    1433,   # MSSQL
    3306,   # MySQL
    5900,   # VNC
    5985,   # WinRM (HTTP)
    5986    # WinRM (HTTPS)
)

Write-Host "Surgically blocking legacy, web, and DB traffic..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "BLUE TEAM BLOCK - Dangerous Ports" `
                    -Direction Inbound `
                    -Action Block `
                    -Protocol TCP `
                    -LocalPort $BlockedPorts `
                    -ErrorAction SilentlyContinue | Out-Null

# 3. The Insurance Policy: Explicitly allow critical AD & Scoring Ports
$AD_TCP_Ports = @(
    53,    # DNS
    88,    # Kerberos (Scored)
    135,   # RPC Endpoint Mapper
    389,   # LDAP (Scored)
    445,   # SMB (SYSVOL/Group Policy)
    464,   # Kerberos Password Change
    636,   # LDAPS
    3268,  # Global Catalog
    3269   # Global Catalog SSL
)

$AD_UDP_Ports = @(53, 88, 389, 464)

Write-Host "Adding insurance allow rules for Scoring Engine and Active Directory..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "BLUE TEAM ALLOW - AD TCP Ports" `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort $AD_TCP_Ports `
                    -ErrorAction SilentlyContinue | Out-Null

New-NetFirewallRule -DisplayName "BLUE TEAM ALLOW - AD UDP Ports" `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort $AD_UDP_Ports `
                    -ErrorAction SilentlyContinue | Out-Null

Write-Host "=== COMPLIANT LOCKDOWN COMPLETE ===" -ForegroundColor Green
