---
date: 2025-03-25
categories: [CTF, ImmersiveLabs]
title: "IML - Halloween 2020: Ep.1 – Death by Ink (PRET)"
tags: ['privilege escalation', 'python', 'rce']

description: "Halloween 2020 Ep.1 – Death by Ink - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Halloween 2020: Ep.1 – Death by Ink (PRET)

This lab is about exploiting port 9100 - used by network printers and using PRET to do it

- After a scan, we see port 9100 is open:

![image1](../resources/2b4871a26ea14ece9d2b9f3325601bd8.png)

- And we have PRET on the Desktop
<https://github.com/RUB-NDS/PRET>

```bash
python3 pret.py 10.102.152.230 pjl

```

![image2](../resources/20e24828c7484ed8970d2faab7a59e76.png)

- If we look in:

![image3](../resources/31a81c0fad38477fb2991c0c627cb76e.png)

- And download list.ps

- We get the flag
