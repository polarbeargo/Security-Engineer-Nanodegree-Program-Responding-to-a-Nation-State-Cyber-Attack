# Security Engineer Nanodegree Program Project: Responding to a Nation State Cyber Attack  

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

```
clamscan -ir -d /home/ubuntu/Downloads/ /home/ubuntu/Downloads/
```
[YARA_rule_log.txt](YARA_rule_log.txt)
### Threat Mitigation  

### Hardening