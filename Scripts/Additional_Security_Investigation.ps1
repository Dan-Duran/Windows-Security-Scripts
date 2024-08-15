#####################################
######### Additional System #########
##### Investigation & Security ######
####### Dan Duran - Rhyno.io ########
#####################################


# Define the output file
$outputFile = "C:\Temp\Additional_Security_Investigation.txt"

# Create or clear the output file
Clear-Content $outputFile -ErrorAction SilentlyContinue
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Function to append output to the file
function Append-Output {
    param (
        [string]$title,
        [ScriptBlock]$command
    )
    "`n# $title" | Out-File -FilePath $outputFile -Append
    try {
        "`n$(& $command | Out-String)" | Out-File -FilePath $outputFile -Append
    } catch {
        "`nError executing command: $_" | Out-File -FilePath $outputFile -Append
    }
}

# 1. Failed Login Attempts (Event ID 4625)
Append-Output "1. Failed Login Attempts (Event ID 4625):" {
    Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object { $_.Id -eq 4625 } | Select-Object TimeCreated, Id, LevelDisplayName, Message
}

# 2. RDP Login Attempts (Failed and Successful - Event IDs 4625 and 4624)
Append-Output "2. RDP Login Attempts (Failed and Successful):" {
    Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625) or (EventID=4624)]]" -MaxEvents 100 | Where-Object { $_.Message -like '*RDP*' } | Select-Object TimeCreated, Id, LevelDisplayName, Message
}

# 3. Users with Administrative Rights
Append-Output "3. Users with Administrative Rights:" {
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource
}

# 4. Group Policy Settings (Output as HTML report)
$gpoReportPath = "C:\Temp\GPOReport.html"
Append-Output "4. Group Policy Settings (Report Path):" {
    try {
        Get-GPOReport -All -ReportType HTML -Path $gpoReportPath
        "Group Policy Report saved at: $gpoReportPath" | Out-String
    } catch {
        "`nGet-GPOReport command not found or error executing it: $_" | Out-String
    }
}

# 5. Network Connections (Netstat)
Append-Output "5. Active Network Connections:" {
    netstat -anob | Out-String
}

# 6. Shared Drives and Active Sessions
Append-Output "6. Shared Drives:" {
    Get-SmbConnection
}
Append-Output "Active Sessions on Shared Folders:" {
    Get-SmbSession | Select-Object ClientComputerName, ClientUserName, SessionId, NumOpens, ConnectedTime, IdleTime
}

# 7. Scheduled Tasks (Running and Ready)
Append-Output "7. Scheduled Tasks (Running and Ready):" {
    Get-ScheduledTask | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'Ready' }
}

# 8. List of Installed Software
Append-Output "8. Installed Software:" {
    Get-WmiObject -Class Win32_Product | Select-Object Name, InstallDate | Sort-Object InstallDate -Descending
}

# 9. Auto-Start Programs (HKLM and HKCU)
Append-Output "9. Auto-Start Programs (HKLM):" {
    Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object PSChildName, Name, Value
}
Append-Output "Auto-Start Programs (HKCU):" {
    Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object PSChildName, Name, Value
}

# 10. Suspicious Registry Entries
Append-Output "10. Suspicious Registry Entries (Startup Programs):" {
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object Name, Value
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object Name, Value
}

# 11. Hosts File Content
Append-Output "11. Hosts File Content:" {
    Get-Content -Path "C:\Windows\System32\drivers\etc\hosts"
}

# 12. Network Interface Details
Append-Output "12. Network Interfaces:" {
    Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed
}

# 13. Firewall Rules
Append-Output "13. Firewall Rules:" {
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Direction, Action, Enabled
}

# 14. PowerShell Logs
Append-Output "14. PowerShell Logs:" {
    Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 20
}

# 15. Active Directory Users (if applicable)
Append-Output "15. Active Directory Users (if applicable):" {
    Try {
        Get-ADUser -Filter *
    }
    Catch {
        "Error: Unable to retrieve Active Directory Users. You might not have the necessary permissions or the computer might not be part of a domain." | Out-String
    }
}

# 16. System Event Logs for Service Changes (Event IDs 7045 and 7035)
Append-Output "16. System Event Logs for Service Changes (Event IDs 7045, 7035):" {
    Get-EventLog -LogName System -Newest 100 | Where-Object { $_.EventID -eq 7045 -or $_.EventID -eq 7035 }
}

# Indicate that the script has finished
"`nScript completed. Check $outputFile for details." | Out-File -FilePath $outputFile -Append

# Open the output file in notepad
Start-Process notepad.exe $outputFile
