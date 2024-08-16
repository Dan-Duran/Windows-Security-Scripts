#####################################
###### Investigate Windows PC #######
####### Dan Duran - Rhyno.io ########
#####################################

# Define the output file
Start-Transcript -Path "C:\Temp\System_Investigation.txt"

# 1. Established Network Connections
Write-Host "1. Established Network Connections:"
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State

# 2. Local User
Write-Host "`n2. Local Users:"
Get-LocalUser

# 3. Active Directory Users
Write-Host "`n3. Active Directory Users:"
Try {
    Get-ADUser -Filter *
}
Catch {
    Write-Host "Error: Unable to retrieve Active Directory Users. You might not have the necessary permissions or the computer might not be part of a domain."
}

# 4. Running Processes
Write-Host "`n4. Running Processes:"
Get-Process | Select-Object Name, Id, Path | Sort-Object Name

# 5. Local Users Detailed Info
Write-Host "`n5. Local Users Detailed Information:"
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Sort-Object PasswordLastSet -Descending

# 6. Enabled Scheduled Tasks
Write-Host "`n6. Enabled Scheduled Tasks:"
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, State, LastRunTime

# 7. Recently Modified Files
Write-Host "`n7. Recently Modified Files (Top 100):"
Get-ChildItem C:\ -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime -First 100

# 8. Failed Logon Attempts (Security Event ID 4625)
Write-Host "`n8. Failed Logon Attempts (Event ID 4625):"
Get-EventLog -LogName Security -InstanceId 4625 -Newest 50

# 9. Running Services
Write-Host "`n9. Running Services:" 
Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status

# 10. System Event Logs for Service Changes (Event IDs 7045 and 7035)
Write-Host "`n10. System Event Logs for Service Changes (Event IDs 7045, 7035):"
Get-EventLog -LogName System -Newest 100 | Where-Object { $_.EventID -eq 7045 -or $_.EventID -eq 7035 }

# 11. Recently Installed Software
Write-Host "`n11. Recently Installed Software:"
Get-WmiObject -Class Win32_Product | Select-Object Name, InstallDate | Sort-Object InstallDate -Descending

# 12. Enabled and Running Scheduled Tasks
Write-Host "`n12. Enabled and Running Scheduled Tasks:"
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | Select-Object TaskName, TaskPath, LastRunTime

# 13. Auto-Start Programs (HKLM)
Write-Host "`n13. Auto-Start Programs (HKLM):"
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object PSChildName, Name, Value

# 14. Auto-Start Programs (HKCU)
Write-Host "`n14. Auto-Start Programs (HKCU):"
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object PSChildName, Name, Value

# 15. Firewall Rules
Write-Host "`n15. Firewall Rules:"
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Direction, Action, Enabled

# 16. PowerShell Logs
Write-Host "`n16. PowerShell Logs:" 
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 20

# 17. Network Interfaces
Write-Host "`n17. Network Interfaces:"
Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed

# Indicate that the script has finished
Write-Host "`nScript completed. Check for details."

Stop-Transcript 
