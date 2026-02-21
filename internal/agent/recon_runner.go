package agent

import (
	"context"
	"fmt"
	"strings"
)

// ReconRunnerConfig は ReconRunner の構築パラメーター。
type ReconRunnerConfig struct {
	Tree       *ReconTree
	TaskMgr    *TaskManager // SubAgent 用（nil = SubAgent 無効）
	Events     chan<- Event
	TargetHost string
	TargetID   int    // TUI イベント用
	MemDir     string // raw output 保存先（空 = 保存しない）
}

// ReconRunner は自動偵察を実行するオーケストレーター。
// リアクティブモデル: evaluateResult が新 HTTP ポートを検出するたびに SpawnWebReconForPort を呼ぶ。
type ReconRunner struct {
	tree       *ReconTree
	taskMgr    *TaskManager
	events     chan<- Event
	targetHost string
	targetID   int
	memDir     string
}

// NewReconRunner は ReconRunner を構築する。
func NewReconRunner(cfg ReconRunnerConfig) *ReconRunner {
	return &ReconRunner{
		tree:       cfg.Tree,
		taskMgr:    cfg.TaskMgr,
		events:     cfg.Events,
		targetHost: cfg.TargetHost,
		targetID:   cfg.TargetID,
		memDir:     cfg.MemDir,
	}
}

// SpawnWebReconForPort は指定ポートの SubAgent を spawn する（リアクティブモデル）。
// max_parallel チェック: active >= MaxParallel なら spawn しない（次の evaluateResult で再試行）。
// Pending タスクだけ InProgress にマークし、SubAgent を起動する。
func (rr *ReconRunner) SpawnWebReconForPort(ctx context.Context, port *ReconNode) {
	if rr.taskMgr == nil {
		rr.emitLog("[RECON] TaskManager not configured — skipping web recon SubAgent")
		return
	}

	// コンテキストキャンセルチェック（StartPortRecon で active を消費する前に確認）
	select {
	case <-ctx.Done():
		return
	default:
	}

	// max_parallel チェック + Pending → InProgress を原子的に実行
	if !rr.tree.StartPortRecon(port) {
		rr.emitLog(fmt.Sprintf("[RECON] Max parallel reached — deferring port %d", port.Port))
		return
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
		ReconTree:  rr.tree,
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

	// カテゴリリストを動的に構築
	var catList strings.Builder
	for _, cat := range MinFuzzCategories {
		fmt.Fprintf(&catList, "     - %s: %s\n", cat.Name, cat.Description)
	}

	return fmt.Sprintf(`You are a web reconnaissance agent for %s (port %d).
Your ReconTree is automatically updated as you run commands.
Check the tree for pending tasks and work through them sequentially.

CRITICAL — THESE FLAGS ARE MANDATORY ON EVERY ffuf COMMAND:
  -of json              (structured output for parsing — NEVER omit)

Do NOT use -recursion or -recursion-depth flags. Each directory is a separate task.

WORKFLOW — Execute tasks in this order for each endpoint:

1. TECHNOLOGY DETECTION (do this FIRST):
   curl -isk %s/
   Examine: Server header, X-Powered-By, Set-Cookie, response body.
   Determine the technology stack (PHP, Java/JSP, Python, ASP.NET, Node.js, Ruby, etc.)
   Choose file extensions based on detected technology. Examples:
     PHP → -e .php,.phtml,.inc     Java → -e .jsp,.do,.action,.jsf
     ASP.NET → -e .aspx,.ashx,.asmx     Python → -e .py
     General → -e .html,.txt,.bak,.xml,.json
   If uncertain, use: -e .php,.jsp,.html,.txt,.bak

2. ENDPOINT ENUMERATION (for each directory):
   ffuf -w <wordlist> -u %s/<path>/FUZZ -e <extensions-from-step-1> -of json -t 50
   When new directories are discovered, enumerate each one separately.

3. ENDPOINT PROFILING:
   For EACH discovered endpoint:
   curl -isk %s/<endpoint>
   Record: response code, headers, body structure, technology indicators.

   After profiling each endpoint:
   - If static file (js/css/jpg/png/ico/svg/woff/font) or Content-Type indicates
     non-dynamic content → skip param_fuzz and value_fuzz for that endpoint
   - If dynamic (PHP/JSP/API/form/redirect/unknown) → proceed with param_fuzz + value_fuzz

4. PARAMETER FUZZING:
   For EACH dynamic endpoint:
   GET: ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "%s/<endpoint>?FUZZ=value" -of json -fs <default-size>
   POST: ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u %s/<endpoint> -X POST -d "FUZZ=value" -of json -fs <default-size>

5. PARAMETER VALUE FUZZING (MANDATORY):
   After discovering parameters in step 4, you MUST test EACH parameter.

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

   Add context-specific payloads based on the parameter name.
   Example: "file" parameter → test OS path payloads, "id" → test more numeric sequences

6. VIRTUAL HOST DISCOVERY:
   First get the default response size:
   curl -s %s | wc -c
   Then fuzz:
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u %s -H "Host: FUZZ.%s" -of json -fs <default-size>
   For each discovered vhost, run endpoint enumeration (step 2) on the vhost.

RULES (VIOLATION = FAILURE):
- EVERY ffuf command MUST include -of json — no exceptions
- Do NOT use -recursion or -recursion-depth flags
- Do NOT skip any endpoint or task
- ALL fuzz categories in step 5 are MANDATORY
- Skip param_fuzz/value_fuzz for static files (js/css/jpg/png/ico/svg/woff/font)
- Report all findings with "memory" action
- When all tasks are complete, use "complete" action to finish
`, host, port, url, url, url, url, url, url, catList.String(), url, url, url, host)
}
