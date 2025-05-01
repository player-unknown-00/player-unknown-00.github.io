---
date: 2025-05-01
categories: [Fixes, Linux]
title: "VirtualBox Kernel Headers Not Found"
tags: ['linux', 'grep']

description: "VirtualBox Kernel Headers Not Found Error"
---

# Grep doesn't give output

When copying a file to KALI from somewhere like Windows, ie. doing:

`schtasks /query /fo LIST /v > tasks.txt`

and then copying it to KALI.

When we check the file:
![image1](../resources/b669fbaf23344366ad441c900764b8a4.png)

We can see that it's UTF-16.
Grep is only compatible with simpler files ie. UTF-8

So it needs to get converted first:

`iconv -f UTF-16 -t UTF-8 tasks.txt > tasks_utf8.txt`

Now we can use grep:
![image2](../resources/8f5aaf3c878d4b58b2cd81603bcceee5.png)

