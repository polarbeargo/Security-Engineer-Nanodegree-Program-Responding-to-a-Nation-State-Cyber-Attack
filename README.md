# Security Engineer Nanodegree Program Project: Responding to a Nation State Cyber Attack  
[image1]: ./starter/section_2/succesful_ssh_logon.png
[image2]: ./starter/section_2/attacker_IP.png
[image3]: ./starter/section_2/Iptable_rule.png
[image4]: ./starter/section_2/remote_config_change.png
[image5]: ./starter/section_2/openvas_vulnerability_report.png
[image6]: ./starter/section_2/ServerTokens.png
[image7]: ./starter/section_2/ServerSignature.png
[image8]: ./starter/section_2/before.png
[image9]: ./starter/section_2/After.png
[image10]: ./starter/section_2/DePrivilegeApacheAccount.png
[image11]: ./starter/section_2/test.png
[image12]: ./starter/section_2/unknown_threatYara.png
[image13]: ./starter/section_2/YARA.png
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
gedit unknown_threat.yara
```
[unknown_threat.yara](unknown_threat.yara)  
![image12]

- Run clamscan under unknown_threat.yara rule that we created.

```
clamscan -ir -d /home/ubuntu/Downloads/ /home/ubuntu/Downloads/
```
[YARA_rule_log.txt](YARA_rule_log.txt)
![image13]
### Threat Mitigation  

- Implement HIDS: Open up Firefox and type the address localhost/ossec. This will launch the Ossec UI. 

    - Connecting to the virtual machine via SSH and notice the new login entry created in the IDS web UI.

```
ssh ubuntu@192.168.56.5
```
![image1]
- Locate Suspicious IP:   
Since the attack happened in the year 2020, and we use the captured the OVA image. We looking for the logs during that time frame.

[attacker_IP.txt](attacker_IP.txt)    
![image2]
- IPtables Rule:  
Identified the attacking IP address, create an IPtables rule to block any SSH connection requests from this host forever.

[Iptable_rule.txt](Iptable_rule.txt)
![image3]
- Detect Backdoor Username, Process & Port:
    - Username: root
    - Process: voldemort
    - Port:

- Disable SSH Root Access: 
    - Disable SSH root access by editing the sshd_config file.

![image4]  
### Hardening  
- OpenVAS Scan: Perform an OpenVAS scan on the target machine and identify the vulnerability that is exploited by the attacker.
![image5]  
- Patching Apache  

    1. By using curl --head localhost, it can display the HTTP headers of the web server. The output should look like this: 

```
Server: Apache/2.4.7 (Ubuntu)
```
![image8]   
2. Edit Apache server configuration file:  

```
su gedit /etc/apache2/conf-enabled/security.conf 
```


3. Scroll down to the “ServerTokens” section where you’ll probably see multiple lines commented out stating “ServerTokens” and different options. Set to Prod.

```
ServerTokens Prod
```
![image6]

4. The next section down should be the “ServerSignature” section set to Off. 

```
ServerSignature Off
```
![image7]

5. Exit the file and save changes.

6. Restart Apache for the changes to take effect.
```
sudo service apache2 restart
```
7. Recheck server HTTP headers with the following:
```
curl --head localhost
```
should see the following:
```
Server: Apache
```
![image9] 

- De-Privilege Apache Account:  
Run the following to create a new group and user for Apache:
```
sudo groupadd apache-group  
sudo adduser apache-user
sudo usermod -g apache-group apache-user
sudo gedit envvars
export APACHE_RUN_USER = apache-user
export APACHE_RUN_GROUP = apache-group
sudo service apache2 restart
```
![image10] 
## test:
```
grep -w apache-group /etc/group
```

show apache-group:x:1001:
```
id apache-user
```
show uid=1001(apache-user) gid=1001(apache-group) groups=1001(apache-group)
![image11] 