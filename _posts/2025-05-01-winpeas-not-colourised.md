---
date: 2025-05-01
categories: [Fixes, Linux]
title: "WinPEAS not colourised"
tags: ['linux', 'vmware']

description: "WinPEAS not colourised"
---

# WinPEAS not colourised

Check Powershell version:

```powershell
$PSVersionTable.PSVersion
```

Need at least version 5.1

```powershell
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Run WinPEAS.exe

