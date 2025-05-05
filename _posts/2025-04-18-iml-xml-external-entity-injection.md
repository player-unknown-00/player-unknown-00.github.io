---
date: 2025-04-18
categories: [CTF, ImmersiveLabs]
title: "IML - XML External Entity Injection"
tags: ['xml', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "XML External Entity Injection - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - XML External Entity Injection


![image1](../resources/899fa60d3ce743aaa23304cb67b852b6.png)

- Copy the contents of the xml


![image2](../resources/c5ec4df93f22417c9191a84e03a27bcf.png)

- Create file and paste the xml data in. Then add the:

```bash
<!DOCTYPE store[<!ENTITY signature SYSTEM "file:///tmp/token.txt" >]>
```

to the top

- Make sure the name next to DOCTYPE correlates with the name in the xml script ie. store
- Add the variable \&signature; somewhere in the script


![image3](../resources/d2f9ccf3ba0540f094d3a79f148e1d5a.png)

- Upload file and choose from dropdown list


![image4](../resources/aaefcaee121f460f850a3e12a762ee74.png)


![image5](../resources/4c423d67ef8c438491b91440017dd342.png)
