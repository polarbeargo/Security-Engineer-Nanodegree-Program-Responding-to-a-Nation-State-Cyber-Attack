# Security Engineer Nanodegree Program Project: Responding to a Nation State Cyber Attack  
[image1]: ./starter/section_2/succesful_ssh_logon.png
### Threat Detection

- ClamAV scan: Perform clamscan on the ‘Downloads’ directory.
```
clamscan -i -r /home/ubuntu/Downloads/
```
[clamAV_report.txt](clamAV_report.txt)
- Suspicious File Identification: Identify the suspicious file in the ‘Downloads’ directory which should have been a cause of infection but managed to defeat your ClamAV scan.

[suspicious_file_report.txt](suspicious_file_report.txt)
- Yara Rule Creation: Create YARA rule to detect the presence of the executable file SSH-One in the ‘Downloads’ directory.
```
vi unknown_threat.yara
```
[unknown_threat.yara](unknown_threat.yara)
- Run clamscan under unknown_threat.yara rule that we created.

```
clamscan -ir -d /home/ubuntu/Downloads/ /home/ubuntu/Downloads/
```
[YARA_rule_log.txt](YARA_rule_log.txt)
### Threat Mitigation  

- Implement HIDS: Open up Firefox and type the address localhost/ossec. This will launch the Ossec UI. 

    - Connecting to the virtual machine via SSH and notice the new login entry created in the IDS web UI.

```
ssh ubuntu@192.168.56.5
```
![image1]
- Locate Suspicious IP


- IPtables Rule

- Detect Backdoor Username, Process & Port
- Disable SSH Root Access

### Hardening