---
date: 2025-05-01
categories: [Fixes, Linux]
title: "Docker error - Invalid interpolation format"
tags: ['linux', 'docker', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Docker error - Invalid interpolation format"
---

# Docker error - Invalid interpolation format

![image1](../resources/934770276d854c4591a338dcdd3901a1.png)

**<u>Fix:</u>**
You need to escape the \$ characters so Docker doesn't try to treat them as variables.

Replace each \$ with \$\$ in the command field of the healthcheck. That tells Docker to pass a literal \$ to the shell.

![image2](../resources/4028f696bce44ba19715eedff2346f48.png)

![image3](../resources/247462e4d5f8487da4ae6fd281a0b1f3.png)

