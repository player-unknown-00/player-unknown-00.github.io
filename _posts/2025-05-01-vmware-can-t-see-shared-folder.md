---
date: 2025-05-01
categories: [Fixes, Linux]
title: "VMWare - Can't see shared folder"
tags: ['linux', 'vmware', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "VMWare - Can't see shared folder"
---

# VMWare - Can't see shared folder

**<u>If you made a shared folder on your Host and then connected it through the VMWare Settings but you still can't see it in your VM:</u>**

```bash
sudo mkdir /mnt/hgfs
vmware-hgfsclient *
```

You should see your shared folder name.

```bash
sudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs -o subtype=vmhgfs-fuse,allow_other
```

Now you will find your shared folder mounted at /mnt/hgfs
