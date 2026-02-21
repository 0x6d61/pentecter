package agent

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// --- nmap XML パーサー ---

// nmapRun は nmap -oX の出力構造
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Ports []nmapPort `xml:"ports>port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// ParseNmapXML は nmap XML 出力をパースし、open ポートを ReconTree に追加する。
func ParseNmapXML(xmlData string, tree *ReconTree) error {
	// XML 部分を抽出（前後にゴミがある場合）
	start := strings.Index(xmlData, "<nmaprun")
	if start < 0 {
		return nil // nmap XML が見つからない
	}
	end := strings.Index(xmlData, "</nmaprun>")
	if end < 0 {
		return nil
	}
	xmlData = xmlData[start : end+len("</nmaprun>")]

	var run nmapRun
	if err := xml.Unmarshal([]byte(xmlData), &run); err != nil {
		return fmt.Errorf("nmap XML parse: %w", err)
	}

	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			banner := port.Service.Product
			if port.Service.Version != "" {
				if banner != "" {
					banner += " "
				}
				banner += port.Service.Version
			}
			tree.AddPort(port.PortID, port.Service.Name, banner)
		}
	}
	return nil
}

// --- nmap テキストパーサー ---

// ParseNmapText は nmap テキスト出力をパースし、open ポートを ReconTree に追加する。
// XML パーサーのフォールバックとして使用。
func ParseNmapText(output string, tree *ReconTree) error {
	// Regex: "22/tcp   open   ssh   OpenSSH 8.2p1..."
	// Format: PORT/PROTO STATE SERVICE VERSION...
	re := regexp.MustCompile(`(?m)^(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)$`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, m := range matches {
		portStr := m[1]
		// state := m[3] // always "open" due to regex
		service := m[4]
		banner := strings.TrimSpace(m[5])

		port := 0
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			continue
		}
		tree.AddPort(port, service, banner)
	}
	return nil
}

// --- ffuf JSON パーサー ---

// ffufOutput は ffuf -of json の出力構造
type ffufOutput struct {
	CommandLine string       `json:"commandline"`
	Results     []ffufResult `json:"results"`
}

type ffufResult struct {
	Input  map[string]string `json:"input"`
	Status int               `json:"status"`
	Length int               `json:"length"`
	URL    string            `json:"url"`
}

// ParseFfufJSON は ffuf JSON 出力をパースし、結果を ReconTree に追加する。
// taskType により追加方法が異なる:
//   - TaskEndpointEnum: 各結果を endpoint として追加
//   - TaskVhostDiscov: 各結果を vhost として追加
//   - TaskParamFuzz: タスクを完了にするのみ
func ParseFfufJSON(jsonData string, tree *ReconTree, host string, port int, parentPath string, taskType ReconTaskType) error {
	// JSON 部分を抽出（前後にゴミがある場合）
	start := strings.Index(jsonData, "{")
	if start < 0 {
		return nil
	}
	jsonData = jsonData[start:]

	var output ffufOutput
	if err := json.Unmarshal([]byte(jsonData), &output); err != nil {
		return fmt.Errorf("ffuf JSON parse: %w", err)
	}

	// 結果が空ならタスクを完了にする
	if len(output.Results) == 0 {
		tree.CompleteTask(host, port, parentPath, taskType)
		return nil
	}

	switch taskType {
	case TaskEndpointEnum:
		for _, r := range output.Results {
			// URL フィールドからフルパスを抽出（再帰対応）
			var newPath string
			if r.URL != "" {
				if parsed, err := url.Parse(r.URL); err == nil && parsed.Path != "" {
					newPath = parsed.Path
				}
			}
			// URL パースに失敗した場合は FUZZ + parentPath にフォールバック
			if newPath == "" {
				fuzz := r.Input["FUZZ"]
				if fuzz == "" {
					continue
				}
				newPath = path.Join(parentPath, fuzz)
			}
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
			// 親パスは URL から算出（再帰 ffuf でも正しい親に配置される）
			parent := path.Dir(newPath)
			if parent == "." {
				parent = "/"
			}
			tree.AddEndpoint(host, port, parent, newPath)
		}
		// 親のenum完了（結果あり = 列挙できた）
		tree.CompleteTask(host, port, parentPath, TaskEndpointEnum)

	case TaskVhostDiscov:
		// vhost 発見: コマンドラインからドメインを抽出
		domain := extractDomainFromFfufCmd(output.CommandLine)
		for _, r := range output.Results {
			fuzz := r.Input["FUZZ"]
			if fuzz == "" {
				continue
			}
			vhostName := fuzz + "." + domain
			tree.AddVhost(host, port, vhostName)
		}
		// 親の vhost discovery 完了
		tree.CompleteTask(host, port, parentPath, TaskVhostDiscov)

	case TaskParamFuzz:
		// パラメータ発見は情報のみ、タスクを完了にする
		tree.CompleteTask(host, port, parentPath, TaskParamFuzz)

	case TaskProfiling:
		tree.CompleteTask(host, port, parentPath, TaskProfiling)
	}

	return nil
}

// extractDomainFromFfufCmd は ffuf コマンドラインから "Host: FUZZ.<domain>" のドメイン部分を抽出する。
func extractDomainFromFfufCmd(cmd string) string {
	// -H "Host: FUZZ.example.com" or -H 'Host: FUZZ.example.com'
	idx := strings.Index(cmd, "FUZZ.")
	if idx < 0 {
		return "unknown"
	}
	rest := cmd[idx+len("FUZZ."):]
	// クォートまたはスペースで終端
	for i, c := range rest {
		if c == '"' || c == '\'' || c == ' ' || c == '\t' {
			return rest[:i]
		}
	}
	return rest
}

// --- 統合検出パーサー ---

// DetectAndParse はコマンドと出力からツールを判定し、適切なパーサーを呼ぶ。
// パーサーが一致しない場合は nil を返す（エラーではない）。
func DetectAndParse(command string, output string, tree *ReconTree, host string) error {
	cmdLower := strings.ToLower(command)

	// nmap 検出
	if strings.Contains(cmdLower, "nmap") {
		if strings.Contains(output, "<nmaprun") {
			return ParseNmapXML(output, tree)
		}
		// XML がない場合はテキストパーサーにフォールバック
		return ParseNmapText(output, tree)
	}

	// ffuf 検出
	if strings.Contains(cmdLower, "ffuf") && strings.Contains(output, `"results"`) {
		port, parentPath, taskType := parseFfufCommand(command)
		return ParseFfufJSON(output, tree, host, port, parentPath, taskType)
	}

	// curl 検出 → profiling 完了
	if strings.Contains(cmdLower, "curl") {
		port, curlPath := parseCurlCommand(command)
		if curlPath != "" {
			tree.CompleteTask(host, port, curlPath, TaskProfiling)
		}
		return nil
	}

	return nil
}

// parseFfufCommand は ffuf コマンドからポート、パス、タスクタイプを抽出する。
func parseFfufCommand(command string) (port int, parentPath string, taskType ReconTaskType) {
	port = 80
	parentPath = "/"
	taskType = TaskEndpointEnum

	// -H "Host:" があれば vhost discovery
	if strings.Contains(command, "Host:") || strings.Contains(command, "host:") {
		taskType = TaskVhostDiscov
		// vhost の場合、-u から port を抽出
		if u := extractURLFromFlag(command, "-u"); u != "" {
			if parsed, err := url.Parse(u); err == nil {
				port = portFromURL(parsed)
			}
		}
		return
	}

	// ?FUZZ= や -d "FUZZ=value" があれば param fuzz
	if strings.Contains(command, "?FUZZ=") || strings.Contains(command, "FUZZ=value") {
		taskType = TaskParamFuzz
	}

	// -u フラグから URL を抽出
	if u := extractURLFromFlag(command, "-u"); u != "" {
		if parsed, err := url.Parse(u); err == nil {
			port = portFromURL(parsed)
			// パスから FUZZ を除去して親パスを得る
			p := parsed.Path
			p = strings.ReplaceAll(p, "/FUZZ", "")
			p = strings.ReplaceAll(p, "FUZZ", "")
			if p == "" {
				p = "/"
			}
			parentPath = p
		}
	}

	return
}

// parseCurlCommand は curl コマンドから URL のポートとパスを抽出する。
func parseCurlCommand(command string) (port int, curlPath string) {
	// curl コマンドから URL を探す
	parts := strings.Fields(command)
	for _, p := range parts {
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			// クォートを除去
			p = strings.Trim(p, `"'`)
			if parsed, err := url.Parse(p); err == nil {
				port = portFromURL(parsed)
				curlPath = parsed.Path
				if curlPath == "" {
					curlPath = "/"
				}
				return
			}
		}
	}
	return 0, ""
}

// ExtractNmapOutputFile は nmap コマンドから出力ファイルパスを抽出する。
// -oX <file> / -oN <file> の場合はそのまま返す。
// -oA <base> の場合は <base>.xml を返す（XML 優先）。
// nmap でなければ、または出力フラグがなければ空文字を返す。
// "-oX -" はパイプ出力なので空文字を返す。
func ExtractNmapOutputFile(command string) string {
	if !strings.Contains(strings.ToLower(command), "nmap") {
		return ""
	}
	parts := strings.Fields(command)
	for i, p := range parts {
		if i+1 >= len(parts) {
			continue
		}
		val := strings.Trim(parts[i+1], `"'`)
		switch p {
		case "-oX", "-oN":
			if val == "-" {
				return "" // stdout 出力
			}
			return val
		case "-oA":
			return val + ".xml"
		}
	}
	return ""
}

// ExtractFfufOutputPath は ffuf コマンドから -o フラグの出力ファイルパスを抽出する。
// ffuf でなければ、または -o がなければ空文字を返す。
// -of（output format）は -o とは別フラグなので混同しない。
func ExtractFfufOutputPath(command string) string {
	if !strings.Contains(strings.ToLower(command), "ffuf") {
		return ""
	}
	parts := strings.Fields(command)
	for i, p := range parts {
		if p == "-o" && i+1 < len(parts) {
			return strings.Trim(parts[i+1], `"'`)
		}
	}
	return ""
}

// EnsureFfufSilent は ffuf コマンドに -s フラグを自動付与する。
// プログレスバー出力を抑制し、TUI のフリーズを防止する。
func EnsureFfufSilent(command string) string {
	if !strings.Contains(command, "ffuf") {
		return command
	}
	if strings.Contains(command, " -s ") || strings.HasSuffix(command, " -s") {
		return command
	}
	// "ffuf" の直後に "-s" を挿入
	return strings.Replace(command, "ffuf ", "ffuf -s ", 1)
}

// extractURLFromFlag はコマンドから指定フラグの値を抽出する。
func extractURLFromFlag(command string, flag string) string {
	parts := strings.Fields(command)
	for i, p := range parts {
		if p == flag && i+1 < len(parts) {
			val := parts[i+1]
			return strings.Trim(val, `"'`)
		}
	}
	return ""
}

// portFromURL は URL からポート番号を返す。明示されていなければスキームから推定。
func portFromURL(u *url.URL) int {
	if u.Port() != "" {
		var port int
		if _, err := fmt.Sscanf(u.Port(), "%d", &port); err == nil {
			return port
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// --- curl メトリクス パーサー ---

// CurlMetrics は curl -w 出力からパースしたレスポンスメトリクス
type CurlMetrics struct {
	StatusCode   int
	ContentSize  int
	ResponseTime float64 // seconds
}

// ParseCurlMetrics は curl -w "%{http_code} %{size_download} %{time_total}" の出力から
// メトリクスを抽出する。最終行からパースを試みる。
// パースできない場合は nil を返す。
func ParseCurlMetrics(output string) *CurlMetrics {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	// 最終行を取得
	lines := strings.Split(output, "\n")
	lastLine := strings.TrimSpace(lines[len(lines)-1])
	if lastLine == "" {
		return nil
	}

	var status, size int
	var responseTime float64
	n, err := fmt.Sscanf(lastLine, "%d %d %f", &status, &size, &responseTime)
	if err != nil || n != 3 {
		return nil
	}

	return &CurlMetrics{
		StatusCode:   status,
		ContentSize:  size,
		ResponseTime: responseTime,
	}
}

// --- ベースライン比較 ---

// Anomaly はベースライン比較で検出された異常
type Anomaly struct {
	Type     string // "status_change", "size_change", "time_change"
	Detail   string // 人間可読な説明
	Severity string // "high", "medium", "low"
}

// CompareBaseline はファジングレスポンスをベースラインと比較し、異常を検出する。
// 検出基準:
//   - ステータスコード変化 → high
//   - コンテンツ長 ±10% 以上 → medium
//   - レスポンス時間 5x 以上遅延 → medium (time-based injection)
func CompareBaseline(baseline, fuzzed *CurlMetrics) []Anomaly {
	var anomalies []Anomaly

	// ステータスコード変化
	if baseline.StatusCode != fuzzed.StatusCode {
		anomalies = append(anomalies, Anomaly{
			Type:     "status_change",
			Detail:   fmt.Sprintf("status changed from %d to %d", baseline.StatusCode, fuzzed.StatusCode),
			Severity: "high",
		})
	}

	// コンテンツサイズ変化（±10%）
	if baseline.ContentSize > 0 {
		diff := fuzzed.ContentSize - baseline.ContentSize
		if diff < 0 {
			diff = -diff
		}
		threshold := float64(baseline.ContentSize) * 0.10
		if float64(diff) > threshold {
			pct := float64(diff) / float64(baseline.ContentSize) * 100
			anomalies = append(anomalies, Anomaly{
				Type:     "size_change",
				Detail:   fmt.Sprintf("size changed from %d to %d (%.0f%%)", baseline.ContentSize, fuzzed.ContentSize, pct),
				Severity: "medium",
			})
		}
	}

	// レスポンス時間変化（5x 以上、ベースライン > 0.01s）
	if baseline.ResponseTime > 0.01 && fuzzed.ResponseTime > baseline.ResponseTime*5 {
		ratio := fuzzed.ResponseTime / baseline.ResponseTime
		anomalies = append(anomalies, Anomaly{
			Type:     "time_change",
			Detail:   fmt.Sprintf("response time %.3fs vs baseline %.3fs (%.1fx slower)", fuzzed.ResponseTime, baseline.ResponseTime, ratio),
			Severity: "medium",
		})
	}

	return anomalies
}
