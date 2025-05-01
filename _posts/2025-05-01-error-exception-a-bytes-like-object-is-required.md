---
date: 2025-05-01
categories: [Fixes, Python]
title: "Error - Exception: a bytes-like object is required"
tags: ['linux', 'python']

description: "Error - Exception: a bytes-like object is required"
---


 # Error - Exception: a bytes-like object is required

- Error:
![image1](../resources/7e6809ad82b14137941ad648eaeee055.png)

The error a bytes-like object is required, not 'str' occurs when you try to perform an operation that expects a bytes object (binary data), but you provide a str object (text).

This issue is common when working with Python 3, as str and bytes are distinct types.

![image2](../resources/b2f7513523324fd9ac5a58cb230f356d.png)

![image3](../resources/8925acb0683e445cae7b238b330fd103.png)

- Fix:

```python
sock.send("Hello, Server!".encode('utf-8'))  # Convert string to bytes
```
