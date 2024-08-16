#####################################
######### Additional System #########
##### Investigation & Security ######
####### Dan Duran - Rhyno.io ########
#####################################


# Define the output file
Start-Transcript -Path "C:\Temp\Additional_Security_Investigation.txt"


# 1. Failed Login Attempts (Event ID 4625)
Write-Host "1. Failed Login Attempts (Event ID 4625):" 
Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object { $_.Id -eq 4625 } | Select-Object TimeCreated, Id, LevelDisplayName, Message


# 2. RDP Login Attempts (Failed and Successful - Event IDs 4625 and 4624)
Write-Host "`n2. RDP Login Attempts (Failed and Successful):" 
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625) or (EventID=4624)]]" -MaxEvents 100 | Where-Object { $_.Message -like '*RDP*' } | Select-Object TimeCreated, Id, LevelDisplayName, Message


# 3. Users with Administrative Rights
Write-Host "`n3. Users with Administrative Rights:"
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource


# 4. Group Policy Settings (Output as HTML report)
$gpoReportPath = "C:\Temp\GPOReport.html"
Write-Host "`n4. Group Policy Settings (Report Path):" 
try {
    Get-GPOReport -All -ReportType HTML -Path $gpoReportPath
    Write-Host "Group Policy Report saved at: $gpoReportPath"
} catch {
    Write-Host "Get-GPOReport command not found or error executing it: $_"
}


# 5. Network Connections (Netstat)
Write-Host "`n5. Active Network Connections:"
netstat -anob | Out-String


# 6. Shared Drives and Active Sessions
Write-Host "`n6. Shared Drives:"
Get-SmbConnection

Write-Host "`nActive Sessions on Shared Folders:"
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, SessionId, NumOpens, ConnectedTime, IdleTime


# 7. Scheduled Tasks (Running and Ready)
Write-Host "`n7. Scheduled Tasks (Running and Ready):"
Get-ScheduledTask | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'Ready' }


# 8. List of Installed Software
Write-Host "`n8. Installed Software:"
Get-WmiObject -Class Win32_Product | Select-Object Name, InstallDate | Sort-Object InstallDate -Descending


# 9. Auto-Start Programs (HKLM)
Write-Host "`n9. Auto-Start Programs (HKLM):"
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'

# 10. Auto-Start Programs (HKCU)
Write-Host "`n10. Auto-Start Programs (HKCU):"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# 11. Hosts File Content
Write-Host "`n11. Hosts File Content:"
Get-Content -Path "C:\Windows\System32\drivers\etc\hosts"

# 12. Network Interface Details
Write-Host "`n12. Network Interfaces:"
Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed

# 13. Firewall Rules
Write-Host "`n13. Firewall Rules:"
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Direction, Action, Enabled

# 14. PowerShell Logs
Write-Host "`n14. PowerShell Logs:"
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 20

# 15. Active Directory Users (if applicable)
Write-Host "`n15. Active Directory Users (if applicable):"
    
Try {
    Get-ADUser -Filter *
}
Catch {
    Write-Host "Error: Unable to retrieve Active Directory Users."
}

# 16. System Event Logs for Service Changes (Event IDs 7045 and 7035)
Write-Host "`n16. System Event Logs for Service Changes (Event IDs 7045, 7035):" 
Get-EventLog -LogName System -Newest 100 | Where-Object { $_.EventID -eq 7045 -or $_.EventID -eq 7035 }

# Indicate that the script has finished
Write-Host "`nScript completed. Check for details."

Stop-Transcript
