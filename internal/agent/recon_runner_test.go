package agent

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestReconRunner_FindHTTPPorts(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(22, "ssh", "OpenSSH")
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(443, "https", "nginx")
	tree.AddPort(3306, "mysql", "MySQL")

	events := make(chan Event, 100)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		Events:     events,
		TargetHost: "10.10.11.100",
	})

	ports := rr.findHTTPPorts()
	if len(ports) != 2 {
		t.Fatalf("HTTP ports = %d, want 2", len(ports))
	}
	if ports[0].Port != 80 {
		t.Errorf("ports[0] = %d, want 80", ports[0].Port)
	}
	if ports[1].Port != 443 {
		t.Errorf("ports[1] = %d, want 443", ports[1].Port)
	}
}

func TestReconRunner_BuildWebReconPrompt(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)
	if !strings.Contains(prompt, "10.10.11.100") {
		t.Error("prompt should contain host")
	}
	if !strings.Contains(prompt, "80") {
		t.Error("prompt should contain port")
	}
	if !strings.Contains(prompt, "ffuf") {
		t.Error("prompt should mention ffuf")
	}
	if !strings.Contains(prompt, "-of json") {
		t.Error("prompt should require json output format")
	}

	// VALUE FUZZING セクションの確認
	if !strings.Contains(prompt, "VALUE FUZZING") {
		t.Error("prompt should contain VALUE FUZZING section")
	}
	if !strings.Contains(prompt, "MANDATORY") {
		t.Error("prompt should mark value fuzzing as MANDATORY")
	}
	if !strings.Contains(prompt, "baseline") {
		t.Error("prompt should mention baseline request")
	}
	// 全カテゴリ名が含まれていること
	for _, cat := range MinFuzzCategories {
		if !strings.Contains(prompt, cat.Name) {
			t.Errorf("prompt missing fuzz category %q", cat.Name)
		}
	}
}

func TestReconRunner_SpawnWebReconForPort_NoTaskMgr(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	events := make(chan Event, 100)

	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		Events:     events,
		TargetHost: "10.10.11.100",
		// TaskMgr is nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rr.SpawnWebReconForPort(ctx, tree.Ports[0])

	// TaskManager が nil なのでスキップログが出る
	found := false
	for len(events) > 0 {
		e := <-events
		if strings.Contains(e.Message, "TaskManager not configured") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should emit log about TaskManager not configured")
	}
}

func TestReconRunner_SpawnWebReconForPort_MaxParallel(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(8080, "http", "Jetty")
	events := make(chan Event, 100)

	// active を MaxParallel に設定 → spawn されない
	tree.SetActiveForTest(2)

	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    &TaskManager{}, // non-nil but no SubBrain → SpawnTask will fail
		Events:     events,
		TargetHost: "10.10.11.100",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rr.SpawnWebReconForPort(ctx, tree.Ports[0])

	// max_parallel 到達のログが出る
	found := false
	for len(events) > 0 {
		e := <-events
		if strings.Contains(e.Message, "Max parallel reached") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should emit log about max parallel reached")
	}

	// active は変わらない（spawn されていない）
	if tree.Active() != 2 {
		t.Errorf("active = %d, want 2 (should not change)", tree.Active())
	}
}

func TestBuildWebReconPrompt_HTTPS(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 443)
	if !strings.Contains(prompt, "https://10.10.11.100") {
		t.Error("prompt for port 443 should use https scheme")
	}
	if !strings.Contains(prompt, "443") {
		t.Error("prompt should contain port number")
	}
}

func TestBuildWebReconPrompt_NonStandardPort(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 8080)
	if !strings.Contains(prompt, "http://10.10.11.100:8080") {
		t.Error("prompt for port 8080 should use http scheme with port")
	}
}

func TestBuildWebReconPrompt_ContainsAllFuzzCategories(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)
	for _, cat := range MinFuzzCategories {
		if !strings.Contains(prompt, cat.Name) {
			t.Errorf("prompt missing category %q", cat.Name)
		}
		if !strings.Contains(prompt, cat.Description) {
			t.Errorf("prompt missing description for %q", cat.Name)
		}
	}
}

func TestBuildWebReconPrompt_NoRecursion(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)
	if strings.Contains(prompt, "-recursion-depth 3") {
		t.Error("prompt should NOT contain -recursion-depth 3")
	}
	if !strings.Contains(prompt, "Do NOT use -recursion") {
		t.Error("prompt should instruct not to use recursion")
	}
}

func TestBuildWebReconPrompt_StaticFileSkip(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)
	if !strings.Contains(prompt, "static file") {
		t.Error("prompt should mention static file skipping")
	}
	if !strings.Contains(prompt, "js/css/jpg") {
		t.Error("prompt should list static file extensions to skip")
	}
}

func TestBuildWebReconPrompt_SequentialTaskInstructions(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)
	if !strings.Contains(prompt, "sequentially") || !strings.Contains(prompt, "each directory") {
		// Check for sequential task processing instructions
		if !strings.Contains(prompt, "separately") {
			t.Error("prompt should instruct sequential/separate task processing for each directory")
		}
	}
	if !strings.Contains(prompt, `"complete" action`) {
		t.Error("prompt should mention complete action for finishing")
	}
}

func TestBuildWebReconPrompt_VhostSubdomainChain(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)

	// vhost 発見後のエンドポイント列挙指示
	if !strings.Contains(prompt, "vhost") || !strings.Contains(prompt, "endpoint enumeration") {
		t.Error("prompt should instruct endpoint enumeration on discovered vhosts")
	}
}

func TestBuildWebReconPrompt_Phase2Instructions(t *testing.T) {
	prompt := buildWebReconPrompt("10.10.11.100", 80)

	// curl -w フォーマット文字列の確認
	if !strings.Contains(prompt, "http_code") {
		t.Error("prompt should contain curl -w format with http_code")
	}
	if !strings.Contains(prompt, "size_download") {
		t.Error("prompt should contain curl -w format with size_download")
	}
	if !strings.Contains(prompt, "time_total") {
		t.Error("prompt should contain curl -w format with time_total")
	}

	// ステータスコード比較の言及
	if !strings.Contains(prompt, "Status code") {
		t.Error("prompt should mention status code comparison")
	}

	// Content-length/size 比較の言及
	if !strings.Contains(prompt, "Content-length") || !strings.Contains(prompt, "10%") {
		t.Error("prompt should mention content-length comparison with threshold")
	}

	// レスポンスタイム比較の言及
	if !strings.Contains(prompt, "Response time") || !strings.Contains(prompt, "5x") {
		t.Error("prompt should mention response time comparison with 5x threshold")
	}

	// memory アクションでの報告
	if !strings.Contains(prompt, `"memory" action`) {
		t.Error("prompt should mention reporting with memory action")
	}

	// severity レベルの言及
	if !strings.Contains(prompt, "severity") {
		t.Error("prompt should mention severity levels for reporting")
	}
}

func TestReconRunner_SpawnWebReconForPort_StartsReconTasks(t *testing.T) {
	// SpawnWebReconForPort が ReconTree の Pending タスクを InProgress にマークすることを確認
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	events := make(chan Event, 100)

	// TaskMgr が nil の場合、StartTask は呼ばれず SpawnWebReconForPort はスキップされる。
	// ここでは nil のときは active が変わらないことを確認。
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    nil,
		Events:     events,
		TargetHost: "10.10.11.100",
		TargetID:   1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rr.SpawnWebReconForPort(ctx, tree.Ports[0])

	// TaskMgr nil → active は 0 のまま
	if tree.Active() != 0 {
		t.Errorf("active = %d, want 0 (TaskMgr nil, StartTask should not be called)", tree.Active())
	}
}
