---
date: 2025-05-01
categories: [Fixes, Linux]
title: "Using mget in SMBClient"
tags: ['linux', 'smbclient', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Using mget in SMBClient"
---

# Using mget in SMBClient

- If you can't use mget in SMB and getting the following error:
![image1](../resources/55ef41adb2a045cf831a48f8230643d9.png)

- Fix with:
```bash
mask ""
recurse ON
prompt OFF
mget *
```

![image2](../resources/76bcdfaf6b7247aebaf3947d3ef6ce71.png)
