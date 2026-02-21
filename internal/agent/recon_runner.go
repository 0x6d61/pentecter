package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ReconRunnerConfig は ReconRunner の構築パラメーター。
type ReconRunnerConfig struct {
	Tree         *ReconTree
	TaskMgr      *TaskManager // SubAgent 用（nil = SubAgent 無効）
	Events       chan<- Event
	InitialScans []string // nmap コマンドリスト
	TargetHost   string
	TargetID     int    // TUI イベント用
	MemDir       string // raw output 保存先（空 = 保存しない）
}

// ReconRunner は自動偵察を実行するオーケストレーター。
type ReconRunner struct {
	tree         *ReconTree
	taskMgr      *TaskManager
	events       chan<- Event
	initialScans []string
	targetHost   string
	targetID     int
	memDir       string
}

// NewReconRunner は ReconRunner を構築する。
func NewReconRunner(cfg ReconRunnerConfig) *ReconRunner {
	return &ReconRunner{
		tree:         cfg.Tree,
		taskMgr:      cfg.TaskMgr,
		events:       cfg.Events,
		initialScans: cfg.InitialScans,
		targetHost:   cfg.TargetHost,
		targetID:     cfg.TargetID,
		memDir:       cfg.MemDir,
	}
}

// Run は自動偵察を実行する（Phase 0 + Phase 1）。
// Loop.Run() から goroutine で呼び出される。
func (rr *ReconRunner) Run(ctx context.Context) {
	rr.RunInitialScans(ctx)
	rr.SpawnWebRecon(ctx)
}

// RunInitialScans は固定 nmap コマンドを順次実行する（Phase 0）。
func (rr *ReconRunner) RunInitialScans(ctx context.Context) {
	for _, scan := range rr.initialScans {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// {target} プレースホルダーを置換
		cmd := strings.ReplaceAll(scan, "{target}", rr.targetHost)

		rr.emitLog(fmt.Sprintf("[RECON] Running: %s", cmd))

		output, err := rr.execCommand(ctx, cmd)
		if err != nil {
			rr.emitLog(fmt.Sprintf("[RECON] Scan error: %v", err))
			continue
		}

		// Raw output 保存
		if rr.memDir != "" {
			if _, saveErr := SaveRawOutput(rr.memDir, rr.targetHost, cmd, output); saveErr != nil {
				rr.emitLog(fmt.Sprintf("[RECON] Raw output save warning: %v", saveErr))
			}
		}

		// パーサーで ReconTree に反映
		if parseErr := DetectAndParse(cmd, output, rr.tree, rr.targetHost); parseErr != nil {
			rr.emitLog(fmt.Sprintf("[RECON] Parse warning: %v", parseErr))
		}

		rr.emitLog(fmt.Sprintf("[RECON] Scan complete: %d ports found", len(rr.tree.Ports)))
	}
}

// SpawnWebRecon は HTTP ポートごとに SubAgent を spawn する（Phase 1）。
func (rr *ReconRunner) SpawnWebRecon(ctx context.Context) {
	httpPorts := rr.findHTTPPorts()
	if len(httpPorts) == 0 {
		rr.emitLog("[RECON] No HTTP ports found — skipping web recon")
		return
	}

	if rr.taskMgr == nil {
		rr.emitLog("[RECON] TaskManager not configured — skipping web recon SubAgents")
		return
	}

	for _, port := range httpPorts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Pending なタスクだけ InProgress にマーク（StatusNone のタスクはスキップ）
		for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
			if port.getReconStatus(tt) == StatusPending {
				task := &ReconTask{Type: tt, Node: port, Host: rr.targetHost, Port: port.Port}
				rr.tree.StartTask(task)
			}
		}

		prompt := buildWebReconPrompt(rr.targetHost, port.Port)
		rr.emitLog(fmt.Sprintf("[RECON] Spawning web recon SubAgent for %s:%d", rr.targetHost, port.Port))

		_, err := rr.taskMgr.SpawnTask(ctx, SpawnTaskRequest{
			Kind:       TaskKindSmart,
			Goal:       fmt.Sprintf("Web reconnaissance on %s:%d", rr.targetHost, port.Port),
			Command:    prompt,
			TargetHost: rr.targetHost,
			TargetID:   rr.targetID,
			MaxTurns:   50,
			Metadata: TaskMetadata{
				Port:    port.Port,
				Service: port.Service,
				Phase:   "web_recon",
			},
		})
		if err != nil {
			rr.emitLog(fmt.Sprintf("[RECON] SubAgent spawn error for :%d: %v", port.Port, err))
		}
	}
}

// findHTTPPorts は ReconTree から HTTP ポートを返す。
func (rr *ReconRunner) findHTTPPorts() []*ReconNode {
	var httpPorts []*ReconNode
	for _, node := range rr.tree.Ports {
		if node.isHTTP() {
			httpPorts = append(httpPorts, node)
		}
	}
	return httpPorts
}

// execCommand はシェルコマンドを実行し、出力を返す。
// command は設定ファイル (initial_scans) 由来の静的コマンドリストであり、
// 外部ユーザー入力からのインジェクションリスクはない。
func (rr *ReconRunner) execCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- command is from static config (initial_scans), not user input
	cmd.Stdin = nil
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// emitLog は TUI にログイベントを送信する。
func (rr *ReconRunner) emitLog(msg string) {
	select {
	case rr.events <- Event{
		Type:     EventLog,
		Source:   SourceSystem,
		Message:  msg,
		TargetID: rr.targetID,
	}:
	default:
	}
}

// buildWebReconPrompt は HTTP ポート用の web recon SubAgent プロンプトを生成する。
func buildWebReconPrompt(host string, port int) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	var url string
	switch port {
	case 80:
		url = fmt.Sprintf("http://%s", host)
	case 443:
		url = fmt.Sprintf("https://%s", host)
	default:
		url = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}

	// Phase 2: カテゴリリストを動的に構築
	var catList strings.Builder
	for _, cat := range MinFuzzCategories {
		fmt.Fprintf(&catList, "     - %s: %s\n", cat.Name, cat.Description)
	}

	return fmt.Sprintf(`You are a web reconnaissance agent for %s (port %d).
Execute these tasks in order using "run" action:

1. ENDPOINT ENUMERATION (recursive):
   ffuf -w /usr/share/wordlists/dirb/common.txt -u %s/FUZZ -e .php,.html,.txt,.bak -of json -t 50
   For EACH directory found, repeat recursively:
   ffuf -w /usr/share/wordlists/dirb/common.txt -u %s/<found-path>/FUZZ -of json -t 50
   Continue until ffuf returns ZERO new results at every level.

2. VIRTUAL HOST DISCOVERY:
   First get the default response size:
   curl -s %s | wc -c
   Then fuzz:
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u %s -H "Host: FUZZ.%s" -of json -fs <default-size>

3. ENDPOINT PROFILING:
   For EACH discovered endpoint, run:
   curl -isk %s/<endpoint>
   Record: response code, headers, body structure, technology indicators.

4. PARAMETER FUZZING:
   For EACH endpoint that accepts input (forms, APIs, query strings):
   GET: ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "%s/<endpoint>?FUZZ=value" -of json -fs <default-size>
   POST: ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u %s/<endpoint> -X POST -d "FUZZ=value" -of json -fs <default-size>

5. PARAMETER VALUE FUZZING (MANDATORY):
   After discovering parameters in step 4, you MUST test EACH parameter with value fuzzing.

   For each discovered parameter:
   a. Send baseline: curl -s -w "\n%%{http_code} %%{size_download} %%{time_total}" "%s/<endpoint>?param=normalvalue"
   b. Record baseline: status_code, content_length, response_time

   MANDATORY categories to test (ALL required):
%s
   For each category:
   1. Choose 2-5 payloads appropriate for the parameter name context
   2. Send: curl -s -w "\n%%{http_code} %%{size_download} %%{time_total}" "%s/<endpoint>?param=PAYLOAD"
   3. Compare against baseline:
      - Status code changed → flag
      - Content-length differs by >10%% → flag
      - Response time >5x baseline → flag (time-based injection)
      - Response body contains error messages, different data, or template output → flag
   4. Report EACH anomaly with "memory" action:
      severity: high/medium/low, title: "param X — category (evidence)"

   Additionally, add context-specific payloads based on the parameter name.
   Example: "file" parameter → test OS path payloads, "id" → test more numeric sequences

IMPORTANT RULES:
- ffuf MUST use -of json flag for structured output
- Continue recursive enumeration until ZERO new results
- Do NOT skip any endpoint or task
- ALL fuzz categories in step 5 are MANDATORY — do NOT skip any category
- Report all findings with "memory" action when complete
`, host, port, url, url, url, url, host, url, url, url, url, catList.String(), url)
}
