---
date: 2025-05-01
categories: [Fixes, Linux]
title: "VMWare Bridging doesn't work"
tags: ['linux', 'vmware']

description: "VMWare Bridging doesn't work"
---

# VMWare Bridging doesn't work

In VMWare:
Edit --\> Virtual Network Editor --\> Edit Settings (prompts for Administrator pass)

VMNet0 should say bridged. Change the value from Automatic (or whatever it is) to a physical network adapter

Apply
OK
