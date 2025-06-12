
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

<img width="1250" alt="Screenshot 2025-06-11 200640" src="https://github.com/user-attachments/assets/335151e5-97d0-4f8b-98e7-aa33f5a92ce4" />

![image](https://github.com/user-attachments/assets/f5376744-0aa6-46c7-9cd5-114bbe0aa36d)

Another query was run to check for any new brute force attempts that occurred in the last hour. Coincidentally, the IP address `193.37.69.105` was attempting to log in to the host `win-vm-mde` at the same time the brute force detection rule was being created. It is very likely that due to the concurrent and very recent activity from the threat actor, Microsoft Sentinel only processed the most recent attacks as the most relevant alerts to be included in this detection rule. The other IP addresses may not be correlated or displayed until the incident has had enough time to fully update. As a result, rather than an issue with the query itself, the cause may have been due to latency and data refresh timing. The Incidents diagram below shows only the host machine `win-vm-mde` and the IP address `193.37.69.105`.

![image](https://github.com/user-attachments/assets/8cb74516-252b-4a8c-aaae-303b37367968)

![image](https://github.com/user-attachments/assets/774cd2fd-e65d-44b6-a707-1dfad8124639)

Despite this technical hiccup, a subsequent query was executed to verify if any of these malicious IP addresses successfully logged in. No successful logons were detected from any of the identified IPs.

![image](https://github.com/user-attachments/assets/02b84c34-c5a8-4f09-97c9-cd8b4f74f16c)


### **Containment Actions**

- The affected VM was isolated using Microsoft Defender for Endpoint (MDE).

<img width="1547" alt="Screenshot 2025-06-11 210357" src="https://github.com/user-attachments/assets/973f0fd2-e37c-416a-bffd-bc3981ccf6fa" />

- A full antimalware scan was performed on the VM through MDE.
- Network Security Group (NSG) rules were tightened to block Remote Desktop Protocol (RDP) access from the public internet, allowing connections only from approved IP addresses.
- A corporate policy has been proposed to enforce this NSG lockdown for all virtual machines moving forward.


### **Closure**

The incident response team has reviewed and confirmed the resolution of the event. All containment and remediation steps have been completed, and relevant findings have been documented. This incident has been classified as a `True Positive – Suspicious Activity`. A brute force attack was detected targeting the `win-vm-mde` host. However, all attempts were unsuccessful, and no unauthorised access was achieved.





