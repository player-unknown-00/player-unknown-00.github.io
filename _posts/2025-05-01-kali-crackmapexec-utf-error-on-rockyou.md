---
date: 2025-05-01
categories: [Fixes, Linux]
title: "Kali - Crackmapexec UTF error on rockyou"
tags: ['linux', 'crackmapexec', 'UTF error', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Kali - Crackmapexec UTF error on rockyou"
---

# Crackmapexec UTF error on Rockyou.txt in Kali Linux


To fix encoding issues, convert the file to UTF-8 using iconv:

```bash
iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt -o rockyou-utf8.txt

sudo cp rockyou-utf8.txt /usr/share/wordlists
```
