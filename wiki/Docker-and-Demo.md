# Docker & Demo

## Demo Environment

The demo environment provides a ready-to-use penetration testing lab with a vulnerable target.

### Architecture

```
┌─────────────────┐     ┌─────────────────────┐
│   pentecter     │     │   metasploitable2    │
│   172.30.0.10   │────▶│   172.30.0.20        │
│                 │     │                      │
│ Tools:          │     │ Vulnerable services: │
│  - nmap         │     │  - vsftpd 2.3.4      │
│  - nikto        │     │  - OpenSSH 4.7p1     │
│  - curl         │     │  - Apache + PHP      │
│  - python3      │     │  - MySQL (no auth)   │
│  - netcat       │     │  - Samba             │
└─────────────────┘     └─────────────────────┘
      pentester_net (172.30.0.0/24)
```

### Starting the Demo

```bash
cd demo

# Set your API key
export ANTHROPIC_API_KEY=sk-ant-xxx...

# Start containers
docker compose up -d

# Connect to pentecter
docker exec -it pentecter pentecter 172.30.0.20
```

### Stopping the Demo

```bash
cd demo
docker compose down
```

### Demo docker-compose.yml

```yaml
services:
  pentecter:
    build: ..
    container_name: pentecter
    networks:
      pentester_net:
        ipv4_address: 172.30.0.10
    environment:
      - ANTHROPIC_API_KEY
    stdin_open: true
    tty: true

  metasploitable2:
    image: tleemcjr/metasploitable2
    container_name: metasploitable2
    networks:
      pentester_net:
        ipv4_address: 172.30.0.20

networks:
  pentester_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

## Docker Tool Execution

Pentecter uses Docker to sandbox tool execution when available.

### Execution Flow

```
Brain decides: "run nmap -sV 10.0.0.5"
  │
  ├─ Tool has Docker config?
  │   ├─ YES → Docker available?
  │   │   ├─ YES → Execute in container (auto-approved)
  │   │   └─ NO → fallback: true?
  │   │       ├─ YES → Execute on host (may need approval)
  │   │       └─ NO → Fail with error
  │   └─ NO → Execute on host (check approval)
  │
  └─ Result returned to agent
```

### Docker Configuration per Tool

Each tool in `tools/*.yaml` can specify Docker settings:

```yaml
docker:
  image: instrumentisto/nmap    # Docker image
  network: host                 # Network mode (host/bridge)
  fallback: true                # Fall back to host if Docker unavailable
```

### Network Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `host` | Container shares host network | Scanning targets on the host network |
| `bridge` | Isolated container network | When network isolation is needed |

## Test Environment (E2E)

For development and E2E testing:

### Setup

```bash
docker compose -f testenv/docker-compose.yml up -d
```

### Exposed Ports (on localhost)

| Host Port | Container Port | Service |
|-----------|---------------|---------|
| 21221 | 21 | FTP (vsftpd 2.3.4, CVE-2011-2523) |
| 22221 | 22 | SSH (OpenSSH 4.7p1) |
| 80221 | 80 | HTTP (Apache + PHP/CGI) |
| 33221 | 3306 | MySQL (no authentication) |

### Running E2E Tests

```bash
# Start test environment
docker compose -f testenv/docker-compose.yml up -d

# Run E2E tests
go test -v -tags=e2e -timeout 300s ./e2e/...

# Clean up
docker compose -f testenv/docker-compose.yml down
```

## Building the Docker Image

The Pentecter Dockerfile includes common penetration testing tools:

```bash
docker build -t pentecter .
```

### Included Tools

The Docker image is based on Debian and includes:
- `nmap` — Port scanning
- `nikto` — Web vulnerability scanning
- `curl` / `wget` — HTTP clients
- `python3` — Scripting
- `netcat` / `socat` — Network utilities
- `hydra` — Credential testing
- `sqlmap` — SQL injection
