---
date: 2025-05-01
categories: [Fixes, Linux]
title: "Snmpwalk error"
tags: ['linux', 'smbclient', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "Snmpwalk error"
---

# Snmpwalk error

![image1](../resources/4246b54dff0649249a284d92d8cc274d.png)

![image2](../resources/754e8dd88dfa4510b6f5149860f7afc9.png)

**<u>Fix:</u>**

```bash
sudo apt update
sudo apt install snmp-mibs-downloader
sudo download-mibs

sudo nano /etc/snmp/snmp.conf
```

Comment out the mibs : line (if present):

![image3](../resources/05913bd683fa4ed7acf6983eb10d1853.png)

```bash
source /etc/snmp/snmp.conf

sudo mv /usr/share/snmp/mibs ~ -rf
git clone https://github.com/librenms/librenms.git
cd librenms
sudo cp mibs /usr/share/snmp/mibs -rf
```

![image4](../resources/3acb73bbbc904f388795ff072b0f2a48.png)

