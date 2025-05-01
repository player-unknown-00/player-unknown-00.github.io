---
date: 2025-05-01
categories: [Fixes, Linux]
title: "Linux - C - Make error - Missing headers"
tags: ['linux', 'c', 'missing headers']

description: "C - Make error - Missing headers"
---


# C - Make error - Missing headers

The error "***No such file or directory: /lib/modules/6.12.13-amd64/build***" means that your system is missing the necessary Linux kernel headers required to compile the driver:
![image1](../resources/3d1cb14fea7845a3affbf198e51878b4.png)

```bash
sudo apt update
sudo apt install linux-headers-$(uname -r) build-essential dkms -y
```