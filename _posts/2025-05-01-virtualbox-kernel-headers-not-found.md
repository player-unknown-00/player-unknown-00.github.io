---
date: 2025-05-01
categories: [Fixes, Linux]
title: "VirtualBox Kernel Headers Not Found"
tags: ['linux', 'virtualbox', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Fix VirtualBox Kernel Headers Not Found Error"
---


# Fix VirtualBox Kernel Headers Not Found Error

The guest additions CD should be inserted into the VM:

```bash
sudo apt-get install build-essential linux-headers-$(uname -r) dkms
reboot
/sbin/rcvboxadd quicksetup all
```

**<u>OR</u>**

```bash
yum install -y "kernel-devel-uname-r == $(uname -r)"
/sbin/rcvboxadd quicksetup all
reboot
```

Something else - desktop type

![image1](../resources/d3f7ae6f7e6641a6bf975c1315b0e3a6.png)

