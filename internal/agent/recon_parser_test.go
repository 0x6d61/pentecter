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

const testFfufRecursiveJSON = `{"commandline":"ffuf -w wordlist -u http://10.10.11.100/api/FUZZ -recursion -recursion-depth 3","results":[{"input":{"FUZZ":"v1"},"status":301,"length":0,"url":"http://10.10.11.100/api/v1"},{"input":{"FUZZ":"users"},"status":200,"length":1234,"url":"http://10.10.11.100/api/v1/users"}]}`

func TestParseFfufJSON_RecursiveURL(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	// /api ノードを事前に追加（親として必要）
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	err := ParseFfufJSON(testFfufRecursiveJSON, tree, "10.10.11.100", 80, "/api", TaskEndpointEnum)
	if err != nil {
		t.Fatal(err)
	}

	// /api ノードの子に /api/v1 が追加される
	apiNode := tree.Ports[0].Children[0] // /api
	if len(apiNode.Children) != 1 {
		t.Fatalf("api Children count = %d, want 1 (/api/v1)", len(apiNode.Children))
	}
	if apiNode.Children[0].Path != "/api/v1" {
		t.Errorf("child path = %q, want /api/v1", apiNode.Children[0].Path)
	}

	// /api/v1 の子に /api/v1/users が追加される
	v1Node := apiNode.Children[0]
	if len(v1Node.Children) != 1 {
		t.Fatalf("v1 Children count = %d, want 1 (/api/v1/users)", len(v1Node.Children))
	}
	if v1Node.Children[0].Path != "/api/v1/users" {
		t.Errorf("child path = %q, want /api/v1/users", v1Node.Children[0].Path)
	}
}

func TestParseFfufJSON_EndpointEnumChildrenStayPending(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	jsonData := `{"commandline":"ffuf -u http://10.10.11.100/FUZZ -of json","results":[
		{"input":{"FUZZ":"admin"},"status":200,"length":1234,"url":"http://10.10.11.100/admin"},
		{"input":{"FUZZ":"api"},"status":200,"length":5678,"url":"http://10.10.11.100/api"}
	]}`

	err := ParseFfufJSON(jsonData, tree, "10.10.11.100", 80, "/", TaskEndpointEnum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parent endpoint_enum should be complete
	portNode := tree.Ports[0]
	if portNode.EndpointEnum != StatusComplete {
		t.Errorf("parent EndpointEnum = %d, want StatusComplete", portNode.EndpointEnum)
	}

	// Children stay pending for HTTPAgent to process
	for _, child := range portNode.Children {
		if child.EndpointEnum != StatusPending {
			t.Errorf("child %s EndpointEnum = %d, want StatusPending", child.Path, child.EndpointEnum)
		}
		// ParamFuzz and Profiling should still be Pending
		if child.ParamFuzz != StatusPending {
			t.Errorf("child %s ParamFuzz = %d, want StatusPending", child.Path, child.ParamFuzz)
		}
		if child.Profiling != StatusPending {
			t.Errorf("child %s Profiling = %d, want StatusPending", child.Path, child.Profiling)
		}
	}
}

func TestParseFfufJSON_RecursiveChildrenStayPending(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	// Recursive ffuf result: /api/v1 and /api/v1/users discovered
	err := ParseFfufJSON(testFfufRecursiveJSON, tree, "10.10.11.100", 80, "/api", TaskEndpointEnum)
	if err != nil {
		t.Fatal(err)
	}

	apiNode := tree.Ports[0].Children[0] // /api
	// /api endpoint_enum should be complete (parent)
	if apiNode.EndpointEnum != StatusComplete {
		t.Errorf("/api EndpointEnum = %d, want StatusComplete", apiNode.EndpointEnum)
	}

	// /api/v1 endpoint_enum should stay pending (HTTPAgent processes each directory separately)
	v1Node := apiNode.Children[0]
	if v1Node.EndpointEnum != StatusPending {
		t.Errorf("/api/v1 EndpointEnum = %d, want StatusPending", v1Node.EndpointEnum)
	}

	// /api/v1/users endpoint_enum should stay pending (HTTPAgent processes each directory separately)
	usersNode := v1Node.Children[0]
	if usersNode.EndpointEnum != StatusPending {
		t.Errorf("/api/v1/users EndpointEnum = %d, want StatusPending", usersNode.EndpointEnum)
	}

	// ParamFuzz and Profiling should still be Pending on all children
	for _, node := range []*ReconNode{v1Node, usersNode} {
		if node.ParamFuzz != StatusPending {
			t.Errorf("%s ParamFuzz = %d, want StatusPending", node.Path, node.ParamFuzz)
		}
		if node.Profiling != StatusPending {
			t.Errorf("%s Profiling = %d, want StatusPending", node.Path, node.Profiling)
		}
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

// --- parseFfufCommand カバレッジ ---

func TestParseFfufCommand_ParamFuzz(t *testing.T) {
	// "?FUZZ=" を含むコマンド → TaskParamFuzz
	cmd := `ffuf -w /usr/share/seclists/params.txt -u "http://10.10.11.100/api?FUZZ=value" -of json`
	port, parentPath, taskType := parseFfufCommand(cmd)

	if taskType != TaskParamFuzz {
		t.Errorf("taskType = %v, want TaskParamFuzz(%v)", taskType, TaskParamFuzz)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
	if parentPath != "/api" {
		t.Errorf("parentPath = %q, want /api", parentPath)
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

// --- extractDomainFromFfufCmd カバレッジ ---

func TestExtractDomainFromFfufCmd_NoFUZZ(t *testing.T) {
	// "FUZZ." が含まれないコマンド → "unknown"
	cmd := `ffuf -w wordlist -u http://10.10.11.100/FUZZ`
	got := extractDomainFromFfufCmd(cmd)
	if got != "unknown" {
		t.Errorf("extractDomainFromFfufCmd = %q, want 'unknown'", got)
	}
}

// --- EnsureFfufSilent テスト ---

func TestEnsureFfufSilent(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			"add -s to ffuf",
			`ffuf -w wordlist -u http://10.10.11.100/FUZZ -of json`,
			`ffuf -s -w wordlist -u http://10.10.11.100/FUZZ -of json`,
		},
		{
			"already has -s",
			`ffuf -s -w wordlist -u http://10.10.11.100/FUZZ -of json`,
			`ffuf -s -w wordlist -u http://10.10.11.100/FUZZ -of json`,
		},
		{
			"not ffuf",
			`nmap -sV 10.10.11.100`,
			`nmap -sV 10.10.11.100`,
		},
		{
			"param fuzz also gets -s",
			`ffuf -w params.txt -u "http://10.10.11.100/api?FUZZ=value" -of json`,
			`ffuf -s -w params.txt -u "http://10.10.11.100/api?FUZZ=value" -of json`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EnsureFfufSilent(tt.command)
			if got != tt.want {
				t.Errorf("EnsureFfufSilent(%q)\n  got:  %q\n  want: %q", tt.command, got, tt.want)
			}
		})
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


// --- ExtractFfufOutputPath テスト ---

func TestExtractFfufOutputPath(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"basic -o flag", `ffuf -w wordlist -u http://10.10.11.100/FUZZ -o /tmp/out.json -of json`, "/tmp/out.json"},
		{"quoted path", `ffuf -w wordlist -o "/tmp/ffuf_out.json" -u http://10.10.11.100/FUZZ`, "/tmp/ffuf_out.json"},
		{"single quoted", `ffuf -w wordlist -o '/tmp/out.json' -u http://10.10.11.100/FUZZ`, "/tmp/out.json"},
		{"no -o flag", `ffuf -w wordlist -u http://10.10.11.100/FUZZ -of json`, ""},
		{"not ffuf", `nmap -p- -oX - 10.10.11.100`, ""},
		{"-of is not -o", `ffuf -w wordlist -u http://10.10.11.100/FUZZ -of json`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFfufOutputPath(tt.command)
			if got != tt.want {
				t.Errorf("ExtractFfufOutputPath(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}
