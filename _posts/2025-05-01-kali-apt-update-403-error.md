---
date: 2025-05-01
categories: [Fixes, Linux]
title: "Kali Apt Update 403 error"
tags: ['linux', 'apt', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Kali Apt Update 403 error"
---

# Kali Apt Update 403 error

![image1](../resources/84327c2fdd99464c85103c15082727fe.png)

**<u>Fix:</u>**

```bash
sudo nano /etc/apt/sources.list
```

Add both lines:

```text
deb-src https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
```

```bash
sudo apt update && sudo apt upgrade -y
```
