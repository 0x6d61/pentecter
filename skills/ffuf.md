---
name: ffuf
description: Web fuzzing — directory/file enumeration, virtual host discovery, parameter fuzzing
---

Use ffuf for directory/file enumeration, virtual host discovery, and parameter fuzzing.

## Directory / File Enumeration

1. Basic directory scan:
   ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<target>/FUZZ

2. With extensions (php, html, txt):
   ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<target>/FUZZ -e .php,.html,.txt,.bak

3. Recursive scan (depth 2):
   ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<target>/FUZZ -recursion -recursion-depth 2

4. Larger wordlist for thorough scan:
   ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<target>/FUZZ

5. Target specific directory:
   ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<target>/api/FUZZ

## Virtual Host (vhost) Discovery

6. Subdomain / vhost scan:
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>"

7. Filter by response size (remove false positives):
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>" -fs <default-size>

8. Workflow: first run without filter to see default size, then filter:
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>" -mc all
   # Note the common response size, then re-run with -fs <size>

## Filtering & Matching

9. Filter by status code (hide 404s):
   ffuf -w wordlist.txt -u http://<target>/FUZZ -fc 404

10. Filter by response size:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -fs 0

11. Filter by word count:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -fw 42

12. Filter by line count:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -fl 10

13. Match only specific status codes:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -mc 200,301,302,403

## Parameter Fuzzing

14. GET parameter fuzzing:
    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<target>/page?FUZZ=value"

15. POST parameter fuzzing:
    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/login -X POST -d "FUZZ=value" -H "Content-Type: application/x-www-form-urlencoded"

16. POST JSON fuzzing:
    ffuf -w wordlist.txt -u http://<target>/api/endpoint -X POST -d '{"FUZZ":"value"}' -H "Content-Type: application/json"

## Authentication & Headers

17. With cookies:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -b "session=abc123"

18. With custom header:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -H "Authorization: Bearer <token>"

19. Through proxy (Burp):
    ffuf -w wordlist.txt -u http://<target>/FUZZ -x http://127.0.0.1:8080

## Performance

20. Control rate (requests per second):
    ffuf -w wordlist.txt -u http://<target>/FUZZ -rate 100

21. Control threads:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -t 50

22. Timeout per request:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -timeout 10

## Output

23. Save results to file:
    ffuf -w wordlist.txt -u http://<target>/FUZZ -o results.json -of json

24. Silent mode (less output):
    ffuf -w wordlist.txt -u http://<target>/FUZZ -s

## Common Wordlists (Kali)

- /usr/share/wordlists/dirb/common.txt (small, fast)
- /usr/share/wordlists/dirb/big.txt (medium)
- /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt (thorough)
- /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt (files)
- /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt (vhost)
- /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt (params)
