---
name: webfuzz
description: Web fuzzing — directory/file enumeration, virtual host discovery, parameter fuzzing (Go native internal tool)
---

Use webfuzz for directory/file enumeration, virtual host discovery, and parameter fuzzing.
webfuzz is a Go-native internal tool — no external binary required. Results are directly written to AttackDataTree.

## Directory / File Enumeration

1. Basic directory scan:
   webfuzz dir -w /usr/share/wordlists/dirb/common.txt -u http://<target>/FUZZ

2. With extensions (php, html, txt):
   webfuzz dir -w /usr/share/wordlists/dirb/common.txt -u http://<target>/FUZZ -e .php,.html,.txt,.bak

3. Target specific directory:
   webfuzz dir -w /usr/share/wordlists/dirb/common.txt -u http://<target>/api/FUZZ

## Virtual Host (vhost) Discovery

4. Subdomain / vhost scan:
   webfuzz vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>"

5. Filter by response size (remove false positives):
   webfuzz vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>" -fs <default-size>

## Filtering & Matching

6. Filter by status code (hide 404s):
   webfuzz dir -w wordlist.txt -u http://<target>/FUZZ -fc 404

7. Filter by response size:
   webfuzz dir -w wordlist.txt -u http://<target>/FUZZ -fs 0

8. Match only specific status codes:
   webfuzz dir -w wordlist.txt -u http://<target>/FUZZ -mc 200,301,302,403

## Parameter Fuzzing

9. GET parameter fuzzing:
   webfuzz param -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<target>/page?FUZZ=value"

10. POST parameter fuzzing:
    webfuzz param -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/login -X POST -d "FUZZ=value"

## Performance

11. Control threads (default: 50):
    webfuzz dir -w wordlist.txt -u http://<target>/FUZZ -t 100

## Common Wordlists (Kali)

- /usr/share/wordlists/dirb/common.txt (small, fast)
- /usr/share/wordlists/dirb/big.txt (medium)
- /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt (vhost)
- /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt (params)
