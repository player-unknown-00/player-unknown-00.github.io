---
date: 2025-05-01
categories: [Fixes, Linux]
title: "SCP Connection closed error"
tags: ['linux', 'scp']

description: "SCP Connection closed error"
---


# SCP Connection closed error

**<u>Error 1:</u>**

![image1](../resources/850a959e24244364b0e28ad4f600ac8f.png)

Fix:
- Find ~/.bashrc or /etc/bash.bashrc
- Remove any command that displays output, ie, echo, cat, etc

![image2](../resources/b99e4a09b56143409eeefaf4540ef8cc.png)

**<u>Error 2:</u>**

![image3](../resources/c98e09bfd0b141b28b6ded71e4b0fd8c.png)

Fix:
- Add **-O** option into scp:

```bash
scp -O -P 2200 n.reed@10.102.69.197:/tmp/sec.txt .
```

Explained here:

<https://unix.stackexchange.com/questions/709613/ssh-working-on-all-devices-but-scp-from-some-devices-gives-connection-closed-e#:~:text=Quick%20version%20(TL%3BDR)>

TL:DR - Since OpenSSH 8.8 the scp utility uses the SFTP protocol by default. The **-O** option must be used to use the legacy SCP protocol.

And in this case, the target is using OpenSSH 8.2:

![image4](../resources/2eeb70689add4e45b6e9cad5fe470b63.png)

