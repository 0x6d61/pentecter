package agent

import (
	"testing"
)

const testNmapXML = `<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
</ports>
</host>
</nmaprun>`

const testFfufDirJSON = `{"commandline":"ffuf -w wordlist -u http://10.10.11.100/FUZZ","results":[{"input":{"FUZZ":"api"},"status":301,"length":0,"url":"http://10.10.11.100/api"},{"input":{"FUZZ":"login"},"status":200,"length":4532,"url":"http://10.10.11.100/login"}]}`

const testFfufEmptyJSON = `{"commandline":"ffuf -w wordlist -u http://10.10.11.100/api/FUZZ","results":[]}`

const testFfufVhostJSON = `{"commandline":"ffuf -w wordlist -u http://10.10.11.100 -H 'Host: FUZZ.example.com'","results":[{"input":{"FUZZ":"dev"},"status":200,"length":1234,"url":"http://10.10.11.100/"},{"input":{"FUZZ":"staging"},"status":200,"length":5678,"url":"http://10.10.11.100/"}]}`

func TestParseNmapXML(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	err := ParseNmapXML(testNmapXML, tree)
	if err != nil {
		t.Fatal(err)
	}

	// open ポートのみ追加される（22, 80）、filtered(443) は除外
	if len(tree.Ports) != 2 {
		t.Fatalf("Ports count = %d, want 2", len(tree.Ports))
	}

	ssh := tree.Ports[0]
	if ssh.Port != 22 || ssh.Service != "ssh" {
		t.Errorf("port 0: %d/%s, want 22/ssh", ssh.Port, ssh.Service)
	}
	if ssh.Banner != "OpenSSH 8.2p1" {
		t.Errorf("banner = %q, want 'OpenSSH 8.2p1'", ssh.Banner)
	}

	http := tree.Ports[1]
	if http.Port != 80 || http.Service != "http" {
		t.Errorf("port 1: %d/%s, want 80/http", http.Port, http.Service)
	}
	if http.Banner != "Apache httpd 2.4.49" {
		t.Errorf("banner = %q, want 'Apache httpd 2.4.49'", http.Banner)
	}
}

func TestParseNmapXML_OnlyOpenPorts(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	_ = ParseNmapXML(testNmapXML, tree)
	// 443 は filtered なので追加されない
	for _, p := range tree.Ports {
		if p.Port == 443 {
			t.Error("filtered port 443 should not be added")
		}
	}
}

func TestParseNmapXML_HTTPGetsPending(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	_ = ParseNmapXML(testNmapXML, tree)

	http := tree.Ports[1] // port 80
	if http.EndpointEnum != StatusPending {
		t.Errorf("HTTP EndpointEnum = %d, want pending", http.EndpointEnum)
	}
	if http.VhostDiscov != StatusPending {
		t.Errorf("HTTP VhostDiscov = %d, want pending", http.VhostDiscov)
	}

	ssh := tree.Ports[0] // port 22
	if ssh.EndpointEnum != StatusNone {
		t.Errorf("SSH EndpointEnum = %d, want none", ssh.EndpointEnum)
	}
}

func TestParseFfufJSON_Endpoints(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	err := ParseFfufJSON(testFfufDirJSON, tree, "10.10.11.100", 80, "/", TaskEndpointEnum)
	if err != nil {
		t.Fatal(err)
	}

	// /api と /login が追加される
	node := tree.Ports[0]
	if len(node.Children) != 2 {
		t.Fatalf("Children count = %d, want 2", len(node.Children))
	}
	if node.Children[0].Path != "/api" {
		t.Errorf("child 0 path = %q, want /api", node.Children[0].Path)
	}
	if node.Children[1].Path != "/login" {
		t.Errorf("child 1 path = %q, want /login", node.Children[1].Path)
	}
}

func TestParseFfufJSON_Empty(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	err := ParseFfufJSON(testFfufEmptyJSON, tree, "10.10.11.100", 80, "/api", TaskEndpointEnum)
	if err != nil {
		t.Fatal(err)
	}

	// 結果ゼロ → タスク完了
	apiNode := tree.Ports[0].Children[0]
	if apiNode.EndpointEnum != StatusComplete {
		t.Errorf("EndpointEnum = %d, want complete", apiNode.EndpointEnum)
	}
}

func TestParseFfufJSON_Vhost(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	err := ParseFfufJSON(testFfufVhostJSON, tree, "10.10.11.100", 80, "", TaskVhostDiscov)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree.Vhosts) != 2 {
		t.Fatalf("Vhosts count = %d, want 2", len(tree.Vhosts))
	}
	if tree.Vhosts[0].Host != "dev.example.com" {
		t.Errorf("vhost 0 = %q, want dev.example.com", tree.Vhosts[0].Host)
	}
	if tree.Vhosts[1].Host != "staging.example.com" {
		t.Errorf("vhost 1 = %q, want staging.example.com", tree.Vhosts[1].Host)
	}
}

func TestDetectAndParse_Nmap(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	err := DetectAndParse("nmap -sV -sC 10.10.11.100", testNmapXML, tree, "10.10.11.100")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Ports) != 2 {
		t.Errorf("Ports count = %d, want 2", len(tree.Ports))
	}
}

func TestDetectAndParse_Ffuf(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	err := DetectAndParse(
		"ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.100/FUZZ",
		testFfufDirJSON,
		tree, "10.10.11.100",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Ports[0].Children) != 2 {
		t.Errorf("Children = %d, want 2", len(tree.Ports[0].Children))
	}
}

func TestDetectAndParse_Curl(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")

	err := DetectAndParse(
		"curl -ik http://10.10.11.100/login",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html",
		tree, "10.10.11.100",
	)
	if err != nil {
		t.Fatal(err)
	}
	loginNode := tree.Ports[0].Children[0]
	if loginNode.Profiling != StatusComplete {
		t.Errorf("Profiling = %d, want complete", loginNode.Profiling)
	}
}

const testNmapText = `Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-01 00:00 UTC
Nmap scan report for 10.10.11.100
Host is up (0.050s latency).

PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http     Apache httpd 2.4.49 ((Unix))
443/tcp  closed   https
3306/tcp open     mysql    MySQL 5.7.36-0ubuntu0.18.04.1
8080/tcp filtered http-proxy

Service detection performed. Please provide correct files.
Nmap done: 1 IP address (1 host up) scanned in 25.43 seconds`

func TestParseNmapText(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	err := ParseNmapText(testNmapText, tree)
	if err != nil {
		t.Fatal(err)
	}

	// open ポートのみ追加（22, 80, 3306）。closed(443), filtered(8080) は除外
	if len(tree.Ports) != 3 {
		t.Fatalf("Ports count = %d, want 3", len(tree.Ports))
	}

	ssh := tree.Ports[0]
	if ssh.Port != 22 || ssh.Service != "ssh" {
		t.Errorf("port 0: %d/%s, want 22/ssh", ssh.Port, ssh.Service)
	}
	if ssh.Banner != "OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)" {
		t.Errorf("ssh banner = %q", ssh.Banner)
	}

	http := tree.Ports[1]
	if http.Port != 80 || http.Service != "http" {
		t.Errorf("port 1: %d/%s, want 80/http", http.Port, http.Service)
	}
	if http.Banner != "Apache httpd 2.4.49 ((Unix))" {
		t.Errorf("http banner = %q", http.Banner)
	}

	mysql := tree.Ports[2]
	if mysql.Port != 3306 || mysql.Service != "mysql" {
		t.Errorf("port 2: %d/%s, want 3306/mysql", mysql.Port, mysql.Service)
	}
}

func TestParseNmapText_HTTPGetsPending(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	_ = ParseNmapText(testNmapText, tree)

	http := tree.Ports[1] // port 80
	if http.EndpointEnum != StatusPending {
		t.Errorf("HTTP EndpointEnum = %d, want pending", http.EndpointEnum)
	}
	if http.VhostDiscov != StatusPending {
		t.Errorf("HTTP VhostDiscov = %d, want pending", http.VhostDiscov)
	}

	ssh := tree.Ports[0] // port 22
	if ssh.EndpointEnum != StatusNone {
		t.Errorf("SSH EndpointEnum = %d, want none", ssh.EndpointEnum)
	}
}

func TestDetectAndParse_NmapText(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	// nmap command without XML output
	err := DetectAndParse("nmap -sV -sC 10.10.11.100", testNmapText, tree, "10.10.11.100")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Ports) != 3 {
		t.Errorf("Ports count = %d, want 3", len(tree.Ports))
	}
}

func TestDetectAndParse_Unknown(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	err := DetectAndParse("echo hello", "hello", tree, "10.10.11.100")
	if err != nil {
		t.Errorf("unknown command should not error, got: %v", err)
	}
}
