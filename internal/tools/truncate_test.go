package tools_test

import (
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/internal/tools"
)

func TestHeadTail_ShortOutput(t *testing.T) {
	lines := makeLines(10)
	cfg := tools.TruncateConfig{Strategy: tools.StrategyHeadTail, HeadLines: 30, TailLines: 20}

	got := tools.Truncate(lines, cfg)

	// 10行しかないので省略なし・全行含まれるはず
	for i, line := range lines {
		if !strings.Contains(got, line) {
			t.Errorf("line %d %q not found in output", i, line)
		}
	}
	if strings.Contains(got, "省略") {
		t.Error("short output should not contain omission marker")
	}
}

func TestHeadTail_LongOutput(t *testing.T) {
	lines := makeLines(100)
	cfg := tools.TruncateConfig{Strategy: tools.StrategyHeadTail, HeadLines: 10, TailLines: 5}

	got := tools.Truncate(lines, cfg)

	// 先頭10行が含まれる
	for i := 0; i < 10; i++ {
		if !strings.Contains(got, lines[i]) {
			t.Errorf("head line %d %q not found", i, lines[i])
		}
	}
	// 末尾5行が含まれる
	for i := 95; i < 100; i++ {
		if !strings.Contains(got, lines[i]) {
			t.Errorf("tail line %d %q not found", i, lines[i])
		}
	}
	// 省略マーカーが含まれる
	if !strings.Contains(got, "省略") {
		t.Error("long output should contain omission marker")
	}
	// 中間行は含まれない
	if strings.Contains(got, lines[50]) {
		t.Errorf("middle line %q should be omitted", lines[50])
	}
}

func TestHTTPResponse_ExtractsHeadersAndBodyHead(t *testing.T) {
	raw := []string{
		"HTTP/1.1 200 OK",
		"Server: Apache/2.4.49",
		"Content-Type: text/html",
		"X-Powered-By: PHP/7.4",
		"",
		"<!DOCTYPE html>",
		"<html><body><h1>Admin Panel</h1></body></html>",
		"more body content here...",
	}
	cfg := tools.TruncateConfig{Strategy: tools.StrategyHTTPResponse, BodyBytes: 50}

	got := tools.Truncate(raw, cfg)

	// ステータス行・ヘッダーは全部含まれる
	if !strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Error("status line not found")
	}
	if !strings.Contains(got, "Server: Apache/2.4.49") {
		t.Error("Server header not found")
	}
	if !strings.Contains(got, "X-Powered-By: PHP/7.4") {
		t.Error("X-Powered-By header not found")
	}
	// ボディ先頭が含まれる
	if !strings.Contains(got, "<!DOCTYPE html>") {
		t.Error("body head not found")
	}
}

// makeLines は n 本のテスト用行スライスを生成する。
func makeLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = strings.Repeat("x", 10) + " line " + itoa(i)
	}
	return lines
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 10)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
