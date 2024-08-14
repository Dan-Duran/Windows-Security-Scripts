# Windows-Security-Scripts
A collection of PowerShell scripts for investigating and securing Windows PCs. These tools help detect potential compromises by analyzing network connections, user accounts, shared folders, scheduled tasks, and system logs, offering both general and in-depth security assessments.

---

## Introduction

This repository contains PowerShell scripts designed to help you investigate and secure a Windows PC, especially if you suspect that the computer might be compromised or infected. These scripts focus on various aspects of system security, including network connections, user accounts, shared folders, scheduled tasks, and system logs. The goal is to gather relevant information to identify potential indicators of compromise and take appropriate action.

---

### Running PowerShell Scripts on Windows

If you encounter errors when running PowerShell scripts due to execution policies, follow these steps to bypass the restrictions temporarily:

1. **Launch PowerShell as Administrator:**
   - Right-click the Start menu and select **Windows PowerShell (Admin)** or **Windows Terminal (Admin)** to open PowerShell with administrative privileges.

2. **Bypass the Execution Policy Temporarily:**
   - To bypass the execution policy for the current PowerShell session without changing the system-wide settings, run the following command:
     ```powershell
     Set-ExecutionPolicy Bypass -Scope Process
     ```
   - This allows you to run scripts without modifying the execution policy for the entire system or user.

3. **Unblock the Script File:**
   - If the script file was downloaded from the internet, you might need to unblock it to remove any security restrictions. Use this command:
     ```powershell
     Unblock-File -Path "C:\Path\To\Your\Script.ps1"
     ```
   - Replace `"C:\Path\To\Your\Script.ps1"` with the actual path to your script file.

4. **Run Your Script:**
   - After performing these steps, you should be able to execute the script without encountering any execution policy errors.

---

### 1. **Investigate-Windows-PC.ps1**

**Purpose:**  
This script is designed to perform a general investigation of a Windows PC to check for potential indicators of compromise. It focuses on gathering information related to user accounts, processes, scheduled tasks, network connections, and recent file modifications.

**Main Actions:**
- **Network Connections:** Lists established network connections to identify any suspicious outbound or inbound connections.
- **User Accounts:** Retrieves details of local users and Active Directory users, if applicable.
- **Processes:** Lists all running processes to check for any unfamiliar or suspicious processes.
- **Scheduled Tasks:** Lists enabled and running scheduled tasks to identify any potential persistence mechanisms.
- **File Modifications:** Lists the most recently modified files, which could indicate recent tampering or data exfiltration.
- **Event Logs:** Checks security logs for failed logon attempts (Event ID 4625) to detect brute-force attempts or unauthorized access.

**Output:**  
The gathered data is saved in a text file (`C:\Temp\System_Investigation.txt`) and opened in Notepad for review.

---

### 2. **Investigate-Shared-Folders.ps1**

**Purpose:**  
This script is focused on investigating shared folders on the local machine. It helps determine which shares are available, who is accessing them, and whether there have been any failed access attempts.

**Main Actions:**
- **Shared Folders:** Lists all shared folders on the machine to identify what resources are being shared.
- **Active Sessions:** Lists all active sessions on the shared folders to see who is currently connected.
- **Open Files:** Displays files currently open on the shared folders to identify what is being accessed.
- **Failed Share Access:** Checks security logs for failed access attempts to shared folders (Event ID 5140).

**Output:**  
The results are saved in a text file (`C:\Temp\Shared_Folders_Investigation.txt`) and opened in Notepad for review.

---

### 3. **Additional_Security_Investigation.ps1**

**Purpose:**  
This is a more extensive script that performs a broad and deep security investigation of the system. It covers a wide range of areas, including network connections, user privileges, group policy settings, shared folders, scheduled tasks, installed software, auto-start programs, registry entries, the hosts file, and more.

**Main Actions:**
- **Failed Logins and RDP Attempts:** Audits security logs for failed login attempts and RDP login attempts, both failed and successful.
- **Administrative Rights:** Lists all users with administrative privileges to ensure there are no unauthorized admin accounts.
- **Group Policy Settings:** Generates a report of all group policy settings, which could be affecting security.
- **Network Connections:** Lists active network connections to detect any unusual communication.
- **Shared Folders:** Lists shared folders and active sessions to see who is accessing what.
- **Scheduled Tasks:** Monitors running and ready scheduled tasks for any potential persistence mechanisms.
- **Installed Software:** Lists all installed software to check for any unauthorized programs.
- **Auto-Start Programs:** Checks both local machine and user registry hives for programs set to start automatically.
- **Suspicious Registry Entries:** Specifically looks at startup-related registry entries that could indicate persistence mechanisms.
- **Hosts File:** Reviews the hosts file to ensure there are no malicious entries redirecting traffic.
- **Network Interfaces:** Provides details on network interfaces, which could reveal unauthorized devices or connections.
- **Firewall Rules:** Lists enabled firewall rules to ensure there are no unexpected exceptions.
- **PowerShell Logs:** Audits PowerShell operational logs to identify potentially malicious PowerShell activity.
- **Service Changes:** Reviews system event logs for any changes to services, which could indicate tampering.

**Output:**  
The results are saved in a text file (`C:\Temp\Additional_Security_Investigation.txt`) and a Group Policy report is saved as an HTML file (`C:\Temp\GPOReport.html`). The text file is automatically opened in Notepad for review.

---

### Summary:
- **Investigate-Windows-PC.ps1:** General system investigation.
- **Investigate-Shared-Folders.ps1:** Focused investigation of shared folders and access attempts.
- **Additional_Security_Investigation.ps1:** In-depth security investigation covering multiple areas of potential concern.

Each script is tailored for specific aspects of system security and investigation, giving you a range of tools to assess and secure your Windows environment.

---

This README now includes an introduction explaining the purpose of the scripts, detailed descriptions of each script's functionality, and instructions for running the scripts while addressing potential execution policy issues.
