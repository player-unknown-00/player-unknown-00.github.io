---
date: 2025-03-09
categories: [CTF, ImmersiveLabs]
title: "IML - Radare2 Reverse Engineering: Ep.2 – Windows Binary Part 2"
tags: ['privilege escalation', 'rce', 'windows', 'radare2', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Radare2 Reverse Engineering Ep.2 - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Radare2 Reverse Engineering: Ep.2 – Windows Binary Part 2

- We can read all the strings in the binary with:

```bash
izz

```

![image1](../resources/293df02d08e2488c971475d18d77a9bb.png)

or to be more precise - we can do:

```bash
izz~password

```

![image2](../resources/48cf52fbef4e480eb56629376b1484d1.png)

- And we get the password:  
  **the_password_token**

- Now if we take the address of the password - we can print out a block starting at that position:

![image3](../resources/9552b2abfca84799b0b38e6fe2d1ad9c.png)

And we get the address of the 7th character

- To get the password compare function we can do:

```bash
f | grep "pass"

```

![image4](../resources/64669ef8cef3421baae257aa0c2b1670.png)
