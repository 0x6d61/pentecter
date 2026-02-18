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
  "thought": "brief reasoning about current situation and next step",
  "action": "run_tool" | "propose" | "think" | "complete",
  "tool": "tool name (only for run_tool or propose)",
  "args": {"key": "value", ...}
}

ARGS FORMAT:
- args is always a JSON object (map), never an array.
- Common keys per tool:
    nmap:   {"target": "10.0.0.5", "ports": "21,22,80", "flags": ["-sV", "-Pn"]}
    nikto:  {"target": "10.0.0.5", "flags": ["-Tuning", "1"]}
    curl:   {"url": "http://10.0.0.5/", "flags": ["-si"]}
    wpscan: {"url": "http://10.0.0.5/", "flags": ["--enumerate", "u"]}
- Array values (e.g., "flags") are expanded as separate CLI arguments.
- Omit keys that are not needed — optional keys will be ignored gracefully.

ACTION TYPES:
- run_tool: Execute a security tool
- propose: Suggest a high-impact action requiring human approval (exploits, brute-force, etc.)
- think: Analyze findings without taking action yet
- complete: Mark the target assessment as done

RULES:
- Always respond with valid JSON only, no prose outside the JSON.
- For destructive or high-impact actions, use "propose" not "run_tool".
- Keep "thought" concise (1-2 sentences).
- Use tool names exactly as registered.`

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
