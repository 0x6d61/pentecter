package agent

import (
	"net/url"
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

func TestParseNmapXML(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
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
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	_ = ParseNmapXML(testNmapXML, tree)
	// 443 は filtered なので追加されない
	for _, p := range tree.Ports {
		if p.Port == 443 {
			t.Error("filtered port 443 should not be added")
		}
	}
}

func TestParseNmapXML_HTTPGetsPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
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

func TestDetectAndParse_Nmap(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	err := DetectAndParse("nmap -sV -sC 10.10.11.100", testNmapXML, tree, "10.10.11.100")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Ports) != 2 {
		t.Errorf("Ports count = %d, want 2", len(tree.Ports))
	}
}

func TestDetectAndParse_Curl(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
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
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
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
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
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
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
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
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	err := DetectAndParse("echo hello", "hello", tree, "10.10.11.100")
	if err != nil {
		t.Errorf("unknown command should not error, got: %v", err)
	}
}

// --- CurlMetrics パーサー テスト ---

func TestParseCurlMetrics_Valid(t *testing.T) {
	m := ParseCurlMetrics("200 1234 0.050")
	if m == nil {
		t.Fatal("expected non-nil CurlMetrics")
	}
	if m.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", m.StatusCode)
	}
	if m.ContentSize != 1234 {
		t.Errorf("ContentSize = %d, want 1234", m.ContentSize)
	}
	if m.ResponseTime != 0.050 {
		t.Errorf("ResponseTime = %f, want 0.050", m.ResponseTime)
	}
}

func TestParseCurlMetrics_WithBody(t *testing.T) {
	output := "<html><body>Hello World</body></html>\n200 1234 0.050"
	m := ParseCurlMetrics(output)
	if m == nil {
		t.Fatal("expected non-nil CurlMetrics")
	}
	if m.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", m.StatusCode)
	}
	if m.ContentSize != 1234 {
		t.Errorf("ContentSize = %d, want 1234", m.ContentSize)
	}
	if m.ResponseTime != 0.050 {
		t.Errorf("ResponseTime = %f, want 0.050", m.ResponseTime)
	}
}

func TestParseCurlMetrics_Invalid(t *testing.T) {
	m := ParseCurlMetrics("this is not metrics data")
	if m != nil {
		t.Errorf("expected nil for invalid input, got %+v", m)
	}
}

func TestParseCurlMetrics_EmptyString(t *testing.T) {
	m := ParseCurlMetrics("")
	if m != nil {
		t.Errorf("expected nil for empty input, got %+v", m)
	}
}

func TestParseCurlMetrics_TrailingNewline(t *testing.T) {
	output := "200 5678 0.123\n"
	m := ParseCurlMetrics(output)
	if m == nil {
		t.Fatal("expected non-nil CurlMetrics")
	}
	if m.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", m.StatusCode)
	}
	if m.ContentSize != 5678 {
		t.Errorf("ContentSize = %d, want 5678", m.ContentSize)
	}
	if m.ResponseTime != 0.123 {
		t.Errorf("ResponseTime = %f, want 0.123", m.ResponseTime)
	}
}

// --- CompareBaseline テスト ---

func TestCompareBaseline_NoAnomaly(t *testing.T) {
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.050}
	fuzzed := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.055}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies, got %d: %+v", len(anomalies), anomalies)
	}
}

func TestCompareBaseline_StatusChange(t *testing.T) {
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.050}
	fuzzed := &CurlMetrics{StatusCode: 500, ContentSize: 1000, ResponseTime: 0.050}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d: %+v", len(anomalies), anomalies)
	}
	if anomalies[0].Type != "status_change" {
		t.Errorf("Type = %q, want status_change", anomalies[0].Type)
	}
	if anomalies[0].Severity != "high" {
		t.Errorf("Severity = %q, want high", anomalies[0].Severity)
	}
}

func TestCompareBaseline_SizeChange(t *testing.T) {
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.050}
	fuzzed := &CurlMetrics{StatusCode: 200, ContentSize: 1200, ResponseTime: 0.050}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d: %+v", len(anomalies), anomalies)
	}
	if anomalies[0].Type != "size_change" {
		t.Errorf("Type = %q, want size_change", anomalies[0].Type)
	}
	if anomalies[0].Severity != "medium" {
		t.Errorf("Severity = %q, want medium", anomalies[0].Severity)
	}
}

func TestCompareBaseline_SizeWithinThreshold(t *testing.T) {
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.050}
	// 5% difference → within 10% threshold
	fuzzed := &CurlMetrics{StatusCode: 200, ContentSize: 1050, ResponseTime: 0.050}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies for 5%% size diff, got %d: %+v", len(anomalies), anomalies)
	}
}

func TestCompareBaseline_TimeChange(t *testing.T) {
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.050}
	fuzzed := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.300}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d: %+v", len(anomalies), anomalies)
	}
	if anomalies[0].Type != "time_change" {
		t.Errorf("Type = %q, want time_change", anomalies[0].Type)
	}
	if anomalies[0].Severity != "medium" {
		t.Errorf("Severity = %q, want medium", anomalies[0].Severity)
	}
}

func TestCompareBaseline_TimeFastBaseline(t *testing.T) {
	// ベースラインが 0.005s（< 0.01s）→ 誤検知防止のため time anomaly なし
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.005}
	fuzzed := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.030}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies for fast baseline, got %d: %+v", len(anomalies), anomalies)
	}
}

func TestCompareBaseline_MultipleAnomalies(t *testing.T) {
	baseline := &CurlMetrics{StatusCode: 200, ContentSize: 1000, ResponseTime: 0.050}
	fuzzed := &CurlMetrics{StatusCode: 500, ContentSize: 2000, ResponseTime: 0.500}

	anomalies := CompareBaseline(baseline, fuzzed)
	if len(anomalies) != 3 {
		t.Fatalf("expected 3 anomalies, got %d: %+v", len(anomalies), anomalies)
	}

	// 各タイプが存在することを確認
	types := make(map[string]bool)
	for _, a := range anomalies {
		types[a.Type] = true
	}
	if !types["status_change"] {
		t.Error("missing status_change anomaly")
	}
	if !types["size_change"] {
		t.Error("missing size_change anomaly")
	}
	if !types["time_change"] {
		t.Error("missing time_change anomaly")
	}
}

// --- portFromURL カバレッジ ---

func TestPortFromURL_ExplicitPort(t *testing.T) {
	// 明示的なポート番号がある場合はそれを返す
	u, err := url.Parse("http://host:8080/path")
	if err != nil {
		t.Fatal(err)
	}
	got := portFromURL(u)
	if got != 8080 {
		t.Errorf("portFromURL(%q) = %d, want 8080", u.String(), got)
	}
}

func TestPortFromURL_HTTPS(t *testing.T) {
	// HTTPS でポート未指定 → 443
	u, err := url.Parse("https://host/path")
	if err != nil {
		t.Fatal(err)
	}
	got := portFromURL(u)
	if got != 443 {
		t.Errorf("portFromURL(%q) = %d, want 443", u.String(), got)
	}
}

func TestPortFromURL_HTTP(t *testing.T) {
	// HTTP でポート未指定 → 80
	u, err := url.Parse("http://host/path")
	if err != nil {
		t.Fatal(err)
	}
	got := portFromURL(u)
	if got != 80 {
		t.Errorf("portFromURL(%q) = %d, want 80", u.String(), got)
	}
}

func TestPortFromURL_HTTPSWithPort(t *testing.T) {
	// HTTPS + 明示ポート → 明示ポートが優先される
	u, err := url.Parse("https://host:9443/path")
	if err != nil {
		t.Fatal(err)
	}
	got := portFromURL(u)
	if got != 9443 {
		t.Errorf("portFromURL(%q) = %d, want 9443", u.String(), got)
	}
}

// --- parseCurlCommand カバレッジ ---

func TestParseCurlCommand_WithPort(t *testing.T) {
	// 非標準ポートの curl コマンド
	cmd := `curl -isk https://10.10.11.100:9443/admin`
	port, curlPath := parseCurlCommand(cmd)
	if port != 9443 {
		t.Errorf("port = %d, want 9443", port)
	}
	if curlPath != "/admin" {
		t.Errorf("path = %q, want /admin", curlPath)
	}
}

func TestParseCurlCommand_NoURL(t *testing.T) {
	// URL がないコマンド → port=0, path=""
	cmd := `curl --help`
	port, curlPath := parseCurlCommand(cmd)
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
	if curlPath != "" {
		t.Errorf("path = %q, want empty", curlPath)
	}
}

// --- ExtractNmapOutputFile テスト ---

func TestExtractNmapOutputFile(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"-oX file", "nmap -sV -oX /tmp/scan.xml 10.10.11.100", "/tmp/scan.xml"},
		{"-oN file", "nmap -sV -oN /tmp/scan.txt 10.10.11.100", "/tmp/scan.txt"},
		{"-oA base", "nmap -sV -oA /tmp/scan 10.10.11.100", "/tmp/scan.xml"},
		{"-oX stdout", "nmap -sV -oX - 10.10.11.100", ""},
		{"no output flag", "nmap -sV 10.10.11.100", ""},
		{"not nmap", "ffuf -w wordlist -u http://10.10.11.100/FUZZ", ""},
		{"quoted path", `nmap -sV -oX "/tmp/scan_out.xml" 10.10.11.100`, "/tmp/scan_out.xml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractNmapOutputFile(tt.command)
			if got != tt.want {
				t.Errorf("ExtractNmapOutputFile(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}
