---
title: Spookifier - 不気味な人
published: 2025-09-08
description: 'There is a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?'
image: ''
tags: ['SSTI','WEB','PYTHON']
category: 'HTB-CHALLENGES'
draft: false 
---

![web logo](./Spookifier-Images/web.png)

> - 3. The current_font list is then combined into a string and append to a list named
all_fonts .
> - 4. Returns the all_fonts list which contains the generated variations.
The generate_render function from the Mako template engine is used to generate an HTML
table with the resultant list:
Since the user-supplied content is not sanitized, we can inject template literals and achieve Server
Side Template Injection (SSTI). We can verify this by submitting the following template expression
```${7*7}``` :


![logo](./Spookifier-Images/ssti.png)

- now i found this payload for show how i can connect to server :
```py
${self.module.cache.util.os.popen('whoami').read()}
```
![whoami](./Spookifier-Images/whoami.png)

> - Now i can change `whoami` to `cat /flag.txt` for read flag !!!

