Below is a detailed set of activities with step-by-step instructions that you can perform using built-in Windows tools and interfaces. This will help you investigate, discover, and analyze potential security issues on a Windows system.

# Investigation Activities

## 1. **Review Running Processes**
   - **Objective:** Identify and investigate suspicious or unknown processes running on the system.
   - **Steps:**
     1. **Open Task Manager:**
        - Right-click on the taskbar and select **Task Manager**.
        - Alternatively, press `Ctrl + Shift + Esc`.
     2. **Check for Unfamiliar Processes:**
        - In the **Processes** tab, scroll through the list of running processes.
        - Look for processes with unfamiliar names or unusually high resource usage.
     3. **Investigate Process Details:**
        - Right-click on any suspicious process and select **Open File Location** to view where the process is running from.
        - Search online for the process name to determine if it’s legitimate.
        - In the **Details** tab, right-click on the process and select **Properties** to check the digital signature under the **Digital Signatures** tab (if present).

## 2. **Examine Auto-Start Programs**
   - **Objective:** Check for unauthorized or suspicious programs that are set to run automatically at startup.
   - **Steps:**
     1. **Open Task Manager:**
        - Right-click on the taskbar and select **Task Manager**.
        - Go to the **Startup** tab.
     2. **Review Startup Programs:**
        - Look through the list of programs that run at startup.
        - Check for unfamiliar or suspicious entries, especially those with a high startup impact.
     3. **Disable Suspicious Entries:**
        - Right-click on any suspicious entries and select **Disable** to prevent them from running at startup.
        - Use **Open File Location** to investigate further, or **Search online** to find more information.

## 3. **Analyze Network Connections**
   - **Objective:** Monitor network connections to identify any unusual or unauthorized communication.
   - **Steps:**
     1. **Open Command Prompt:**
        - Press `Win + R`, type `cmd`, and press Enter.
     2. **List Active Connections:**
        - Type the following command and press Enter:
          ```cmd
          netstat -anob
          ```
        - This will list all active network connections, along with the process IDs (PIDs) that are using them.
     3. **Identify Suspicious Connections:**
        - Look for connections to unfamiliar IP addresses, especially those with a foreign address.
        - Note the PID of any suspicious connection and cross-reference it with the processes in Task Manager.

## 4. **Review Scheduled Tasks**
   - **Objective:** Identify and investigate scheduled tasks that could be used for persistence or unauthorized activity.
   - **Steps:**
     1. **Open Task Scheduler:**
        - Press `Win + R`, type `taskschd.msc`, and press Enter.
     2. **Browse Through Scheduled Tasks:**
        - In the left pane, expand **Task Scheduler Library**.
        - Browse through the folders and tasks, paying attention to tasks that run programs or scripts.
     3. **Investigate Suspicious Tasks:**
        - Right-click on any suspicious task and select **Properties**.
        - Check the **Actions** tab to see what program or script the task runs.
        - Note the **Triggers** tab to see when the task is scheduled to run.
     4. **Disable or Delete Suspicious Tasks:**
        - If you find a task that seems suspicious, you can **Disable** or **Delete** it by right-clicking on the task.

## 5. **Check Event Logs for Suspicious Activity**
   - **Objective:** Review Windows Event Logs for signs of compromise, such as failed logon attempts, service changes, or script execution.
   - **Steps:**
     1. **Open Event Viewer:**
        - Press `Win + R`, type `eventvwr`, and press Enter.
     2. **Check Security Logs:**
        - In the left pane, navigate to **Windows Logs > Security**.
        - Look for **Event ID 4625** (failed logon attempts) and **Event ID 4624** (successful logons).
     3. **Check System Logs:**
        - Navigate to **Windows Logs > System**.
        - Look for **Event ID 7045** (a service was installed) and **Event ID 7035** (a service was started).
     4. **Filter Logs for Specific Events:**
        - Right-click on a log (e.g., Security), select **Filter Current Log**, and enter the Event IDs you’re interested in.
        - This helps narrow down relevant events for investigation.

## 6. **Review User Accounts**
   - **Objective:** Verify that there are no unauthorized or suspicious user accounts, especially those with administrative privileges.
   - **Steps:**
     1. **Open Local Users and Groups:**
        - Press `Win + R`, type `lusrmgr.msc`, and press Enter.
        - Navigate to **Users** under **Local Users and Groups**.
     2. **Review User Accounts:**
        - Check the list of user accounts for unfamiliar names.
        - Pay special attention to accounts that are members of the **Administrators** group.
     3. **Disable or Remove Unauthorized Accounts:**
        - Right-click on any suspicious account and select **Properties**.
        - You can **Disable** the account by selecting **Account is disabled** or delete the account if it's confirmed as unauthorized.

## 7. **Examine the Hosts File**
   - **Objective:** Check the Windows Hosts file for unauthorized entries that could redirect traffic or block access to legitimate sites.
   - **Steps:**
     1. **Open the Hosts File:**
        - Press `Win + R`, type `notepad`, and press Enter.
        - In Notepad, click **File > Open** and navigate to `C:\Windows\System32\drivers\etc`.
        - Change the file type dropdown to **All Files** and select the **hosts** file.
     2. **Review the Hosts File:**
        - Look for any unfamiliar entries, especially those that redirect commonly used sites (like Google or antivirus update sites) to a different IP address.
     3. **Remove Suspicious Entries:**
        - Delete any unauthorized entries and save the file.

## 8. **Inspect Browser History and Extensions**
   - **Objective:** Review browser history and installed extensions to detect signs of phishing, malware, or unauthorized access.
   - **Steps:**
     1. **Open the Browser (e.g., Chrome, Edge):**
        - Launch your web browser.
     2. **Check Browser History:**
        - Press `Ctrl + H` to open the browser history.
        - Look for visits to suspicious sites, phishing pages, or sites you don’t recognize.
     3. **Review Installed Extensions:**
        - Go to the browser menu and navigate to **Extensions**.
        - Review the list of installed extensions for any that you didn’t install or that seem suspicious.
        - Remove any unwanted or suspicious extensions.

## 9. **Inspect Recently Installed Software**
   - **Objective:** Check for any recently installed software that could be malicious or unwanted.
   - **Steps:**
     1. **Open Control Panel:**
        - Press `Win + R`, type `control`, and press Enter.
        - Navigate to **Programs > Programs and Features**.
     2. **Sort by Installation Date:**
        - Click on the **Installed On** column to sort the list of installed programs by date.
        - Look for any unfamiliar or suspicious software installed recently.
     3. **Uninstall Suspicious Software:**
        - Select the software and click **Uninstall** to remove it.

## 10. **Check for Unauthorized Remote Connections**
   - **Objective:** Detect and investigate any unauthorized remote connections to the system.
   - **Steps:**
     1. **Open Command Prompt:**
        - Press `Win + R`, type `cmd`, and press Enter.
     2. **List Remote Sessions:**
        - Type the following command and press Enter:
          ```cmd
          query user
          ```
        - This will list all active user sessions, including those connected remotely.
     3. **Identify Unauthorized Connections:**
        - Check the list for any sessions connected remotely (usually indicated under the **SESSIONNAME** column).
        - If you find an unfamiliar session, note the **ID** and username.
     4. **Log Off Unauthorized Sessions:**
        - Use the following command to log off a suspicious session:
          ```cmd
          logoff <ID>
          ```
        - Replace `<ID>` with the session ID of the suspicious connection.

