---
date: 2025-05-01
categories: [Fixes, Linux]
title: "PRET - Error dumping NVRAM"
tags: ['linux', 'pret', 'printer', 'nvram', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "PRET - Error dumping NVRAM"
---

# PRET - Error dumping NVRAM

When running nvram dump:

![image1](../resources/6b56e75425d04504aa8ee646cbc82d80.png)

**<u>Fixes:</u>**

<u>In pjl.py - line 741:</u>

- Change:

```python
file().write(lpath, "") # empty file
```

to

```python
file().write(lpath, b"") # empty file
```

![image2](../resources/00a49b43c8ff4a9080f0cd263ac0c4a2.png)

In helper.py - line 406 - append function:

- Change append function to:

```python
def append(self, path, data):
    # Ensure data is in bytes format
    if isinstance(data, str):
        data = data.encode('utf-8')
    self.write(path, data, 'ab+')
```

![image3](../resources/0930d0bd0f414273a13971a3ffb66c89.png)

- Now it works:

![image4](../resources/ee306445aa344c59be031e4f913f6421.png)

