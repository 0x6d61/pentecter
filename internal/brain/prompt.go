package brain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// systemPrompt はペンテスト特化のシステムプロンプト。
// Brain は常にこのプロンプトをシステムメッセージとして受け取る。
const systemPrompt = `You are Pentecter, an autonomous penetration testing agent operating under authorized engagements.

Your role is to analyze the current target state and decide the next action.

RESPONSE FORMAT (strict JSON, no markdown):
{
  "thought": "brief reasoning",
  "action": "run" | "propose" | "think" | "complete" | "memory",
  "command": "full CLI command string (for run and propose)",
  "memory": {"type":"vulnerability|credential|artifact|note","title":"...","description":"...","severity":"critical|high|medium|low|info"}
}

ACTION TYPES:
- run:      Execute a command inside a Docker sandbox. Use for safe, sandboxed tools (nmap, nikto, curl, etc.)
- propose:  Suggest a command that runs directly on the host. Requires human approval. Use for exploits, brute-force, host-side tools (msfconsole, etc.)
- think:    Analyze findings without taking action
- complete: Mark the target assessment as done
- memory:   Record a finding (vulnerability, credential, artifact) to the knowledge base

RULES:
- Always respond with valid JSON only, no prose outside JSON.
- Use "run" for tools that run in Docker containers (sandboxed, auto-approved).
- Use "propose" for tools that run directly on the host (require human y/n approval).
- Write the full CLI command in "command" field, exactly as you would type it in a shell.
- Record important findings with "memory" action before completing.
- Keep "thought" concise (1-2 sentences).

EXAMPLES:
{"thought":"starting port scan","action":"run","command":"nmap -sV -p 21,22,80,443 10.0.0.5"}
{"thought":"web vuln scan","action":"run","command":"nikto -h http://10.0.0.5/"}
{"thought":"found credentials, try SSH","action":"propose","command":"ssh admin@10.0.0.5"}
{"thought":"found CVE-2021-41773","action":"memory","memory":{"type":"vulnerability","title":"CVE-2021-41773","description":"Apache 2.4.49 Path Traversal confirmed","severity":"critical"}}`

// buildPrompt はターゲット状態とツール出力からユーザープロンプトを組み立てる。
func buildPrompt(input Input) string {
	var sb strings.Builder

	sb.WriteString("## Current Target State\n")
	sb.WriteString("```json\n")
	sb.WriteString(input.TargetSnapshot)
	sb.WriteString("\n```\n")

	if input.ToolOutput != "" {
		sb.WriteString("\n## Last Tool Output\n")
		sb.WriteString("```\n")
		sb.WriteString(input.ToolOutput)
		sb.WriteString("\n```\n")
	}

	if input.UserMessage != "" {
		sb.WriteString("\n## User Instruction\n")
		sb.WriteString(input.UserMessage)
		sb.WriteString("\n")
	}

	sb.WriteString("\nDecide the next action and respond with JSON only.")
	return sb.String()
}

// jsonBlockRe は LLM がコードブロックで JSON を返した場合に抽出するパターン。
var jsonBlockRe = regexp.MustCompile("(?s)```(?:json)?\\s*({.*?})\\s*```")

// parseActionJSON は LLM のレスポンステキストから schema.Action を抽出・パースする。
// LLM が JSON をコードブロックで囲んで返した場合も処理する。
func parseActionJSON(text string) (*schema.Action, error) {
	text = strings.TrimSpace(text)

	// コードブロック内の JSON を取り出す試み
	if m := jsonBlockRe.FindStringSubmatch(text); len(m) > 1 {
		text = m[1]
	}

	// 先頭の { から末尾の } までを抽出（前後にテキストがある場合の対策）
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		text = text[start : end+1]
	}

	var action schema.Action
	if err := json.Unmarshal([]byte(text), &action); err != nil {
		return nil, fmt.Errorf("invalid JSON from LLM: %w\nraw: %s", err, text)
	}

	if action.Action == "" {
		return nil, fmt.Errorf("LLM response missing 'action' field: %s", text)
	}

	return &action, nil
}
