package brain

import (
	"encoding/json"
	"fmt"
	"strings"
)

// extractTargetPrompt はユーザーテキストからターゲットホストを抽出するためのシステムプロンプト。
const extractTargetPrompt = `You are a helper that extracts target host information from user input.
Given a user's message, extract:
1. The target host (IP address or domain name) they want to test
2. Any remaining instruction for the assessment

Respond with JSON only:
{"host": "extracted.host.com", "instruction": "remaining instruction text"}

If no host is found, return:
{"host": "", "instruction": "original text"}

Examples:
- "eighteen.htbを攻略して" → {"host": "eighteen.htb", "instruction": "攻略して"}
- "会社のサーバー 192.168.1.1 をスキャンして" → {"host": "192.168.1.1", "instruction": "会社のサーバーをスキャンして"}
- "Webサーバーのセキュリティを診断" → {"host": "", "instruction": "Webサーバーのセキュリティを診断"}
`

// extractTargetResponse は ExtractTarget のレスポンス JSON 構造体。
type extractTargetResponse struct {
	Host        string `json:"host"`
	Instruction string `json:"instruction"`
}

// parseExtractTargetResponse は LLM のレスポンステキストからホストとインストラクションを抽出する。
// parseActionJSON と同様のコードブロック除去 + {〜} 抽出ロジックを使用する。
func parseExtractTargetResponse(text string) (host, instruction string, err error) {
	text = strings.TrimSpace(text)

	// コードブロック内の JSON を取り出す
	if m := jsonBlockRe.FindStringSubmatch(text); len(m) > 1 {
		text = m[1]
	}

	// 先頭の { から末尾の } までを抽出
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		text = text[start : end+1]
	}

	var resp extractTargetResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		return "", "", fmt.Errorf("extract target: invalid JSON from LLM: %w\nraw: %s", err, text)
	}

	return resp.Host, resp.Instruction, nil
}
