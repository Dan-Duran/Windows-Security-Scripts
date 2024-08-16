#####################################
######## List Shared Drives ########
####### Dan Duran - Rhyno.io ########
#####################################

# Define the output file
Start-Transcript -Path "C:\Temp\Shared_Drives_Investigation.txt"
 
# 1. List all shared folders on the local machine
Write-Host "1. Shared Drives:"
Get-SmbConnection

# 2. List active sessions on shared folders
Write-Host "`n2. Active Sessions on Shared Drives:"
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, SessionId, NumOpens, ConnectedTime, IdleTime

# 3. List open files on shared folders
Write-Host "`n3. Open Files on Shared Drives:" 
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path, SessionId, Dialect, NumLocks

# 4. Review Security Event Logs for Failed Share Access (Event ID 5140)
Write-Host "`n4. Security Event Logs for Failed Share Access (Event ID 5140):"
Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object { $_.Id -eq 5140 } | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 50

# Indicate that the script has finished
Write-Host "`nScript completed. Check for details."

Stop-Transcript
