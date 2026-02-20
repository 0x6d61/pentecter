---
name: ssh
description: SSH connection, tunneling, and pivoting techniques
---

Use SSH for connecting, tunneling, port forwarding, and pivoting.

## Connection

1. Password auth:
   ssh user@<target>
   sshpass -p '<pass>' ssh -o StrictHostKeyChecking=no user@<target>  # nosemgrep: detected-ssh-password

2. Key auth:
   ssh -i id_rsa user@<target>
   chmod 600 id_rsa  (fix permissions if needed)

3. Non-standard port:
   ssh -p 2222 user@<target>

4. Force password auth (disable key):
   ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@<target>

## Enumeration

5. Banner grab:
   nmap -sV -p22 <target>
   nc -vn <target> 22

6. Enumerate auth methods:
   ssh -v user@<target> 2>&1 | grep "Authentications that can continue"

7. Check for weak keys:
   ssh-audit <target>

## Port Forwarding

8. Local port forward (access remote service through local port):
   ssh -L 8080:127.0.0.1:80 user@<target>
   # Now access http://127.0.0.1:8080 to reach target's port 80

9. Local forward to internal host (pivot):
   ssh -L 3306:10.10.10.5:3306 user@<target>
   # Access internal host 10.10.10.5:3306 via localhost:3306

10. Remote port forward (expose local service to target):
    ssh -R 4444:127.0.0.1:4444 user@<target>
    # Target can reach attacker's port 4444 via its own localhost:4444

11. Dynamic SOCKS proxy (full pivot):
    ssh -D 1080 user@<target>
    # Configure proxychains: socks5 127.0.0.1 1080
    proxychains nmap -sT 10.10.10.0/24

## File Transfer

12. SCP download:
    scp user@<target>:/path/to/file ./local_file

13. SCP upload:
    scp ./local_file user@<target>:/tmp/

14. SCP with key:
    scp -i id_rsa user@<target>:/etc/passwd ./

15. SFTP interactive:
    sftp user@<target>

## SSH Key Operations

16. Generate key pair:
    ssh-keygen -t rsa -b 4096 -f ./id_rsa -N ""

17. Add public key to target (persistence):
    echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

18. Extract private key from found files:
    find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null

## Tunneling Chains

19. ProxyJump (SSH through jump host):
    ssh -J user1@jump:22 user2@internal

20. SSH over SSH tunnel:
    ssh -L 2222:internal:22 user@jump
    ssh -p 2222 user@127.0.0.1

## Common Exploits

21. OpenSSH < 7.7 username enumeration (CVE-2018-15473):
    python3 ssh_user_enum.py <target> -w /usr/share/wordlists/names.txt

22. libssh auth bypass (CVE-2018-10933):
    python3 libssh_bypass.py <target>
