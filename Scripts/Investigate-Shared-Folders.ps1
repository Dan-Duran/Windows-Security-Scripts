#####################################
######## List Shared Folders ########
####### Dan Duran - Rhyno.io ########
#####################################

# Define the output file
$outputFile = "C:\Temp\Shared_Folders_Investigation.txt"

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

# 1. List all shared folders on the local machine
Append-Output "Shared Folders:" {
    Get-SmbShare | Select-Object Name, Path, Description, State
}

# 2. List active sessions on shared folders
Append-Output "Active Sessions on Shared Folders:" {
    Get-SmbSession | Select-Object ClientComputerName, ClientUserName, SessionId, NumOpens, ConnectedTime, IdleTime
}

# 3. List open files on shared folders
Append-Output "Open Files on Shared Folders:" {
    Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path, SessionId, Dialect, NumLocks
}

# 4. Review Security Event Logs for Failed Share Access (Event ID 5140)
Append-Output "Security Event Logs for Failed Share Access (Event ID 5140):" {
    Get-WinEvent -LogName Security -FilterHashtable @{Id=5140} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message
}

# Indicate that the script has finished
"`nScript completed. Check $outputFile for details." | Out-File -FilePath $outputFile -Append

# Open the output file in notepad
Start-Process notepad.exe $outputFile
