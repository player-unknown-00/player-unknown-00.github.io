---
date: 2025-05-01
categories: [Fixes, Windows]
title: "Beep from Acer laptop charger being connected"
tags: ['Windows', 'Acer']

description: "Beep from Acer laptop charger being connected"
---

# Beep from Acer laptop charger being connected

The charging beep on Acer laptops can be annoying, but you can disable it in a few ways:

**Method 1: Disable Beep in BIOS**
1.  **Restart** your laptop and enter the BIOS/UEFI.
    - **Press F2 (or Del) repeatedly while booting up.**
2.  Look for an option related to **Charger Beep**, **Battery Warning Sound**, or similar.
3.  **Disable it** and save changes (F10 to save and exit).
4.  **Reboot** and check if the beep is gone.

**Method 2: Disable Beep via Device Manager**
1.  **Press** Win + X and select **Device Manager**.
2.  **Expand** System Devices.
3.  **Find** System Speaker or Beep.
4.  **Right-click** and select **Disable**.

**Method 3: Disable Beep via Registry Editor**
1.  **Press** Win + R, type regedit, and hit **Enter**.
2.  Navigate to:  
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep
3.  Double-click Start and **change the value to 4** (disables beep).
4.  **Restart** your laptop.

**Method 4: Disable Beep via Command Prompt**
1.  Open **Command Prompt as Admin** (Win + X → Command Prompt (Admin)).
2.  Run the following command:  
    net stop beep
3.  To permanently disable it, run:  
    sc config beep start= disabled
