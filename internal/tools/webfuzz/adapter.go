package webfuzz

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

// TreeUpdater は AttackDataTree への書き込みを抽象化するインターフェース。
// agent パッケージへの直接依存を避けるために使用する。
type TreeUpdater interface {
	AddEndpointWithStatus(host string, port int, parentPath, newPath string, httpStatus int)
	AddVhost(parentHost string, port int, vhostName string)
	CompleteTask(host string, port int, path string, taskType int)
	AddParameter(host string, port int, path string, name string, paramType string)
	AddFinding(host string, port int, path string, param, category, evidence, severity string)
}

// WebfuzzTool は InternalTool を実装し、結果を AttackDataTree に直接書き込む。
type WebfuzzTool struct {
	tree TreeUpdater
	host string
}

// NewWebfuzzTool は WebfuzzTool を構築する。
// tree が nil の場合、ヒットはコールバックのみで通知される（ツリー更新なし）。
func NewWebfuzzTool(tree TreeUpdater, host string) *WebfuzzTool {
	return &WebfuzzTool{tree: tree, host: host}
}

// Execute は InternalTool インターフェースを実装する。
// args はサブコマンドとフラグ（例: ["dir", "-u", "http://...", "-w", "..."]）。
func (w *WebfuzzTool) Execute(ctx context.Context, args []string, lineCh chan<- tools.OutputLine) (int, error) {
	opts, err := ParseArgs(args)
	if err != nil {
		errLine := tools.OutputLine{
			Time:    time.Now(),
			Content: fmt.Sprintf("[ERROR] %v", err),
			IsError: true,
		}
		select {
		case lineCh <- errLine:
		default:
		}
		return 1, err
	}

	hitFn := func(hit Hit) {
		if w.tree == nil {
			return
		}
		port, parentPath := extractPortAndPath(opts.URL)
		switch opts.Mode {
		case "dir":
			// ヒットの URL からフルパスを抽出
			newPath := extractPathFromHitURL(hit.URL, parentPath, hit.Input)
			parent := path.Dir(newPath)
			if parent == "." {
				parent = "/"
			}
			w.tree.AddEndpointWithStatus(w.host, port, parent, newPath, hit.StatusCode)
		case "vhost":
			domain := extractDomainFromHeaders(opts.Headers)
			vhostName := hit.Input + "." + domain
			w.tree.AddVhost(w.host, port, vhostName)
		case "param":
			// ヒットしたパラメーター名をツリーに記録
			w.tree.AddParameter(w.host, port, parentPath, hit.Input, "query")
		}
	}

	lineFn := func(line string) {
		select {
		case lineCh <- tools.OutputLine{
			Time:    time.Now(),
			Content: line,
		}:
		default:
		}
	}

	if err := Run(ctx, opts, hitFn, lineFn); err != nil {
		return 1, err
	}

	// 各モードの列挙完了をマーク
	if w.tree != nil {
		port, parentPath := extractPortAndPath(opts.URL)
		switch opts.Mode {
		case "dir":
			// TaskEndpointEnum = 0 (agent パッケージの定数値)
			w.tree.CompleteTask(w.host, port, parentPath, 0)
		case "vhost":
			// TaskVhostDiscov = 4 (agent パッケージの定数値)
			w.tree.CompleteTask(w.host, port, parentPath, 4)
		case "param":
			// TaskParamFuzz = 1 (agent パッケージの定数値)
			w.tree.CompleteTask(w.host, port, parentPath, 1)
		}
	}

	return 0, nil
}

// extractPortAndPath は URL からポート番号とパス（FUZZ 除去済み）を抽出する。
func extractPortAndPath(rawURL string) (int, string) {
	// FUZZ を除去してからパース
	cleanURL := strings.ReplaceAll(rawURL, "FUZZ", "")
	// クエリパラメーターの ? を除去
	cleanURL = strings.TrimRight(cleanURL, "?=&")

	parsed, err := url.Parse(cleanURL)
	if err != nil {
		return 80, "/"
	}

	port := 80
	if parsed.Port() != "" {
		var p int
		if _, err := fmt.Sscanf(parsed.Port(), "%d", &p); err == nil {
			port = p
		}
	} else if parsed.Scheme == "https" {
		port = 443
	}

	p := parsed.Path
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	return port, p
}

// extractPathFromHitURL は Hit の URL からフルパスを抽出する。
func extractPathFromHitURL(hitURL, parentPath, input string) string {
	parsed, err := url.Parse(hitURL)
	if err == nil && parsed.Path != "" {
		newPath := parsed.Path
		if !strings.HasPrefix(newPath, "/") {
			newPath = "/" + newPath
		}
		return newPath
	}
	// フォールバック: parentPath + input
	newPath := path.Join(parentPath, input)
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}
	return newPath
}

// extractDomainFromHeaders は -H "Host: FUZZ.<domain>" からドメイン部分を抽出する。
func extractDomainFromHeaders(headers []string) string {
	for _, h := range headers {
		if idx := strings.Index(h, "FUZZ."); idx >= 0 {
			rest := h[idx+len("FUZZ."):]
			// クォートまたはスペースで終端
			for i, c := range rest {
				if c == '"' || c == '\'' || c == ' ' || c == '\t' {
					return rest[:i]
				}
			}
			return rest
		}
	}
	return "unknown"
}
