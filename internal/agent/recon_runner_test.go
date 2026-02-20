package agent

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestReconRunner_RunInitialScans(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	events := make(chan Event, 100)

	rr := NewReconRunner(ReconRunnerConfig{
		Tree:         tree,
		Events:       events,
		InitialScans: []string{"echo '<nmaprun><host><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\" product=\"Apache\"/></port></ports></host></nmaprun>'"},
		TargetHost:   "10.10.11.100",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rr.RunInitialScans(ctx)

	// nmap XML パースで port 80 が追加される
	if len(tree.Ports) != 1 {
		t.Fatalf("Ports count = %d, want 1", len(tree.Ports))
	}
	if tree.Ports[0].Port != 80 {
		t.Errorf("Port = %d, want 80", tree.Ports[0].Port)
	}
}

func TestReconRunner_RunInitialScans_Placeholder(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	events := make(chan Event, 100)

	rr := NewReconRunner(ReconRunnerConfig{
		Tree:         tree,
		Events:       events,
		InitialScans: []string{"echo {target}"},
		TargetHost:   "10.10.11.100",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rr.RunInitialScans(ctx)

	// {target} が置換されたことを確認（イベントログから）
	found := false
	for len(events) > 0 {
		e := <-events
		if strings.Contains(e.Message, "10.10.11.100") {
			found = true
			break
		}
	}
	if !found {
		t.Error("target placeholder should be replaced in command")
	}
}

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
}

func TestReconRunner_RunInitialScans_ContextCancel(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	events := make(chan Event, 100)

	rr := NewReconRunner(ReconRunnerConfig{
		Tree:         tree,
		Events:       events,
		InitialScans: []string{"sleep 10", "echo done"},
		TargetHost:   "10.10.11.100",
	})

	ctx, cancel := context.WithCancel(context.Background())
	// 即キャンセルして2つ目のコマンドが実行されないことを確認
	cancel()

	rr.RunInitialScans(ctx)

	// キャンセル済みなので何もパースされない
	if len(tree.Ports) != 0 {
		t.Errorf("Ports count = %d, want 0 (context was cancelled)", len(tree.Ports))
	}
}

func TestReconRunner_SpawnWebRecon_NoTaskMgr(t *testing.T) {
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

	rr.SpawnWebRecon(ctx)

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

func TestReconRunner_SpawnWebRecon_NoHTTPPorts(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(22, "ssh", "OpenSSH")
	events := make(chan Event, 100)

	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		Events:     events,
		TargetHost: "10.10.11.100",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rr.SpawnWebRecon(ctx)

	// HTTP ポートがないのでスキップログが出る
	found := false
	for len(events) > 0 {
		e := <-events
		if strings.Contains(e.Message, "No HTTP ports found") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should emit log about no HTTP ports found")
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
