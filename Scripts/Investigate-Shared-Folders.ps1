#####################################
######## List Shared Drives ########
####### Dan Duran - Rhyno.io ########
#####################################

# Define the output file
$outputFile = "C:\Temp\Shared_Drives_Investigation.txt"


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
    "`n$($command.Invoke() | Out-String)" | Out-File -FilePath $outputFile -Append
}


# 1. List all shared folders on the local machine
Append-Output "1. Shared Drives:" {
    Get-SmbConnection
}

# 2. List active sessions on shared folders
Append-Output "2. Active Sessions on Shared Drives:" {
    Get-SmbSession | Select-Object ClientComputerName, ClientUserName, SessionId, NumOpens, ConnectedTime, IdleTime
}

# 3. List open files on shared folders
Append-Output "3. Open Files on Shared Drives:" {
    Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path, SessionId, Dialect, NumLocks
}

# 4. Review Security Event Logs for Failed Share Access (Event ID 5140)
Append-Output "4. Security Event Logs for Failed Share Access (Event ID 5140):" {
    Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object { $_.Id -eq 5140 } | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 50
}



# Indicate that the script has finished
"`nScript completed. Check $outputFile for details." | Out-File -FilePath $outputFile -Append

# Open the output file in notepad
Start-Process notepad.exe $outputFile
