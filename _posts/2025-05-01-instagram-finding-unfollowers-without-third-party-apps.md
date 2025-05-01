---
date: 2025-05-01
categories: [Fixes, Instagram]
title: "Instagram - Finding Unfollowers without third party apps"
tags: ['instagram', 'followers']

description: "Finding Unfollowers without third party apps"
---

# Instagram - Finding Unfollowers without third party apps

On the app:
- Open the Instagram app and go to your profile.
- Tap the three-line menu icon in the top-right corner.
- Select **Your Activity** \> **Download Your Information**.
- Enter your email address and follow the prompts to request your data.​

**<u>On Linux or Windows WSL:</u>**

```bash
grep -o '<a[^>]*>[^<]*</a>' following.html | sed -e 's/<[^>]*>//g' > following_names.txt
sort following_names.txt > sorted_names.txt
diff <file1> <file2> | grep ">"
```

