---
date: 2025-05-02
categories: [Fixes, Linux]
title: "VMWare - Kali - Out of space"
tags: ['linux', 'vmware', 'tryhackme', 'hackthebox', 'immersivelabs', 'thm', 'iml', 'htb']

description: "VMWare - Kali - Out of space"
---

VMWare - Kali - Out of space

- Create a COPY not snapshot of the VM, just in case (as you will need to delete all snapshots before expanding the hard disk)

- In VMWare:
VM -\> Settings -\> Hard Disk -\> Expand

- Start VM

- If VM hangs on a black screen:
  - Restart VM and choose Advanced options during boot and choose Recovery Mode
  - Enter root password
  - **Check your partitions to ensure they are correctly set up.**  
    sudo fdisk -l  
    This will show the current partitions. Look for /dev/sda1 and verify its size. If it doesn’t span the entire disk, you'll need to resize it.

- **Resize the Partition (If Necessary)**
If the partition does not span the full disk, follow these steps:
- **Use fdisk to modify the partition**:  
  sudo fdisk /dev/sda
- Type **p** to print the current partition table and verify that /dev/sda1 exists.
- Delete the partition (this won’t erase your data, just the partition table entry):
  - Type **d** and choose the partition (likely /dev/sda1).
- Recreate the partition:
  - Type **n** to create a new partition.
  - Choose **p** for primary.
  - **Select the default options** to create a partition that spans the entire disk (make sure it uses the entire space).
  - **Do NOT** delete the Signature, when prompted, enter **N**
  - Type **w** to write the partition table.

- **Resize the Filesystem**
After recreating the partition, you need to resize the filesystem to match the new partition size.
- **Resize the filesystem**:
Run the following command to resize the filesystem on /dev/sda1:  

```bash
sudo resize2fs /dev/sda1  
```

This will resize the filesystem to use the newly available space.

```bash
sudo reboot
```