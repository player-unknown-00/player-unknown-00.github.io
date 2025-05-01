---
date: 2025-03-27
categories: [CTF, ImmersiveLabs]
title: "IML - Python Coding Network Challenge Ep. 2&3"
tags: ['privilege escalation', 'python', 'rce']

description: "Python Coding Network Challenge Ep. 2&3 - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Python Coding Network Challenge Ep. 2&3

Can get to it from here:
<https://endeavour.immersivelabs.online/objectives/objective/354d11850f9748feaf33a5e3a2f9b3a1/labs>

As you don't seem to be able to search for this challenge

Note - It says:

![image1](../resources/1aa68653663b477cb070851fcbed3ee0.png)

But you can get this token from either Ep.2 or Ep.3

**<u>Ep.1</u>**

- Ep.1 - Source code:

![image2](../resources/9012a33c55284418974ad135a52c4be8.png)
- Ep.1 Token:

![image3](../resources/67719270fffe4c7a8099440da03806c8.png)

**<u>Ep.2</u>**

- Ep.2 Source code:

![image4](../resources/295d699674a8411685d539392339e271.png)

- Ep.2 Token:

![image5](../resources/606ced034d6347739e566a173e247409.png)

**<u>Ep.3</u>**

- Source code:

![image6](../resources/b15bed0e83a2431d9a3760cbe8e223f7.png)
- This one is a bit more advance - we need to look at this line:

```python
dk = hashlib.pbkdf2_hmac('sha256', bytes(os.environ.get('level_2_secret_token'),'utf-8'), b'12345', randint(100,199))

```

- If we look at the python hashlib docs - we can see what each part does:

![image7](../resources/76a5ff50b4b74ff9b2878bc88fbdeaa3.png)

We are particularly interested in the last part - the random number of iterations

- So all we need to do is create a for loop and hash every number between 100 and 199 (inclusive):

![image8](../resources/15ecc4d88de341268069a1b59f7b0c85.png)

- Token:

![image9](../resources/2bec40c7cced456faa4fd58390367623.png)
