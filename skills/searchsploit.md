---
name: searchsploit
description: Search ExploitDB for known exploits using searchsploit
---

Use searchsploit to find known exploits, PoCs, and shellcode from ExploitDB.

## Basic Search

1. Search by software name and version:
   searchsploit apache 2.4.49
   searchsploit openssh 8.0
   searchsploit vsftpd 2.3.4

2. Search by CVE:
   searchsploit --cve 2021-41773
   searchsploit --cve 2018-15473

3. Search with exact match (avoid noise):
   searchsploit -e "Apache 2.4.49"

## Output Control

4. Show full path to exploit files:
   searchsploit -p 12345

5. JSON output (machine-readable):
   searchsploit --json apache 2.4.49

6. Show only exploits (exclude shellcode/papers):
   searchsploit -t apache 2.4.49

7. Exclude results containing a term:
   searchsploit apache 2.4 --exclude="Denial of Service"

## Copy & Use Exploits

8. Copy exploit to current directory:
   searchsploit -m 50383
   searchsploit -m exploits/linux/remote/50383.py

9. Examine exploit before running:
   searchsploit -x 50383

## Workflow: nmap to searchsploit

10. Parse nmap XML output directly:
    nmap -sV -oX nmap_output.xml <target>
    searchsploit --nmap nmap_output.xml

11. Manual workflow (recommended):
    # Step 1: Identify services
    nmap -sV <target>
    # Step 2: Search for each service version
    searchsploit "OpenSSH 8.0"
    searchsploit "Apache httpd 2.4.49"
    searchsploit "ProFTPD 1.3.5"
    # Step 3: Copy promising exploit
    searchsploit -m <exploit-id>
    # Step 4: Read and adapt
    cat <exploit-file>

## Update Database

12. Update ExploitDB database:
    searchsploit -u

## Tips

- Always search with version numbers for precise results
- Use `searchsploit -m` to copy, never modify the original DB files
- Check exploit language (Python 2 vs 3, Ruby, etc.) before running
- Read the exploit source — some need target-specific modifications
- Combine with `searchsploit --nmap` for automated bulk lookups after scans
