---
date: 2025-04-12
categories: [CTF, IML]
title: "IML - Cross-Site Scripting: Ep.3 – Stored XSS"
tags: ['privilege escalation', 'rce', 'xss']

description: "Cross-Site Scripting Ep.3 – S - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Cross-Site Scripting: Ep.3 – Stored XSS


![image1](../resources/506b5ad51e814f3fb46cfc6e75cb04e7.png)

![image2](../resources/b7bee66356d9418cb0c2b9c7599f6518.png)

- Review field is vulnerable

- Close the \<p\> tag and enter script tag
```javascript
</p><script>alert(11)</script>
```

![image3](../resources/ce195c3d9e2c44258c32b662d1edae1d.png)


![image4](../resources/bd9dc290ac0d4865845036142fe35bdc.png)