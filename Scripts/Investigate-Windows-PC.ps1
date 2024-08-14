#####################################
###### Investigate Windows PC #######
####### Dan Duran - Rhyno.io ########
#####################################

# Define the output file
$outputFile = "C:\Temp\System_Investigation.txt"

# Create or clear the output file
Clear-Content $outputFile -ErrorAction SilentlyContinue
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Function to append output to the file
function Append-Output {
    param (
        [string]$title,
        [scriptblock]$command
    )
    "`n$title`n$($command | Out-String)" | Out-File -FilePath $outputFile -Append
}

# 1. Established Network Connections
Append-Output "Established Network Connections:" {
    Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
}

# 2. Local Users
Append-Output "Local Users:" {
    Get-LocalUser
}

# 3. Active Directory Users
Append-Output "Active Directory Users:" {
    Try {
        Get-ADUser -Filter *
    }
    Catch {
        "Error: Unable to retrieve Active Directory Users. You might not have the necessary permissions or the computer might not be part of a domain." | Out-String
    }
}

# 4. Running Processes
Append-Output "Running Processes:" {
    Get-Process | Select-Object Name, Id, Path | Sort-Object Name
}

# 5. Local Users Detailed Info
Append-Output "Local Users Detailed Information:" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Sort-Object PasswordLastSet -Descending
}

# 6. Enabled Scheduled Tasks
Append-Output "Enabled Scheduled Tasks:" {
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, State, LastRunTime
}

# 7. Recently Modified Files
Append-Output "Recently Modified Files (Top 100):" {
    Get-ChildItem C:\ -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime -First 100
}

# 8. Failed Logon Attempts (Security Event ID 4625)
Append-Output "Failed Logon Attempts (Event ID 4625):" {
    Get-EventLog -LogName Security -InstanceId 4625 -Newest 50
}

# 9. Running Services
Append-Output "Running Services:" {
    Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status
}

# 10. System Event Logs for Service Changes (Event IDs 7045 and 7035)
Append-Output "System Event Logs for Service Changes (Event IDs 7045, 7035):" {
    Get-EventLog -LogName System -Newest 100 | Where-Object { $_.EventID -eq 7045 -or $_.EventID -eq 7035 }
}

# 11. Recently Installed Software
Append-Output "Recently Installed Software:" {
    Get-WmiObject -Class Win32_Product | Select-Object Name, InstallDate | Sort-Object InstallDate -Descending
}

# 12. Enabled and Running Scheduled Tasks
Append-Output "Enabled and Running Scheduled Tasks:" {
    Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | Select-Object TaskName, TaskPath, LastRunTime
}

# 13. Auto-Start Programs (HKLM)
Append-Output "Auto-Start Programs (HKLM):" {
    Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object PSChildName, Name, Value
}

# 14. Auto-Start Programs (HKCU)
Append-Output "Auto-Start Programs (HKCU):" {
    Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object PSChildName, Name, Value
}

# 15. Firewall Rules
Append-Output "Firewall Rules:" {
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Direction, Action, Enabled
}

# 16. PowerShell Logs
Append-Output "PowerShell Logs:" {
    Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 20
}

# 17. Network Interfaces
Append-Output "Network Interfaces:" {
    Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed
}

# Indicate that the script has finished
"`nScript completed. Check $outputFile for details." | Out-File -FilePath $outputFile -Append

# Open the output file in notepad
Start-Process notepad.exe $outputFile
