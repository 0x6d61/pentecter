package webfuzz

import (
	"strings"
	"testing"
	"time"
)

func TestParseArgs_BasicDir(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ", "-w", "/path/to/wordlist.txt"}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Mode != "dir" {
		t.Errorf("Mode = %q, want %q", opts.Mode, "dir")
	}
	if opts.URL != "http://example.com/FUZZ" {
		t.Errorf("URL = %q, want %q", opts.URL, "http://example.com/FUZZ")
	}
	if opts.Wordlist != "/path/to/wordlist.txt" {
		t.Errorf("Wordlist = %q, want %q", opts.Wordlist, "/path/to/wordlist.txt")
	}
	if opts.Method != "GET" {
		t.Errorf("Method = %q, want %q", opts.Method, "GET")
	}
	if opts.Threads != 50 {
		t.Errorf("Threads = %d, want %d", opts.Threads, 50)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want %v", opts.Timeout, 10*time.Second)
	}
	if len(opts.MatchStatus) != len(DefaultMatchStatus) {
		t.Errorf("MatchStatus length = %d, want %d", len(opts.MatchStatus), len(DefaultMatchStatus))
	}
	for i, v := range DefaultMatchStatus {
		if opts.MatchStatus[i] != v {
			t.Errorf("MatchStatus[%d] = %d, want %d", i, opts.MatchStatus[i], v)
		}
	}
}

func TestParseArgs_AllOptions(t *testing.T) {
	args := []string{
		"dir",
		"-u", "http://example.com/FUZZ",
		"-w", "/wordlist.txt",
		"-X", "POST",
		"-d", "key=FUZZ",
		"-H", "Content-Type: application/json",
		"-H", "Authorization: Bearer token123",
		"-e", ".php,.html,.txt",
		"-t", "100",
		"-fc", "404,500",
		"-fs", "4242,0",
		"-mc", "200,301",
	}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Method != "POST" {
		t.Errorf("Method = %q, want %q", opts.Method, "POST")
	}
	if opts.Data != "key=FUZZ" {
		t.Errorf("Data = %q, want %q", opts.Data, "key=FUZZ")
	}
	if len(opts.Headers) != 2 {
		t.Fatalf("Headers length = %d, want 2", len(opts.Headers))
	}
	if opts.Headers[0] != "Content-Type: application/json" {
		t.Errorf("Headers[0] = %q, want %q", opts.Headers[0], "Content-Type: application/json")
	}
	if opts.Headers[1] != "Authorization: Bearer token123" {
		t.Errorf("Headers[1] = %q, want %q", opts.Headers[1], "Authorization: Bearer token123")
	}
	wantExts := []string{".php", ".html", ".txt"}
	if len(opts.Extensions) != len(wantExts) {
		t.Fatalf("Extensions length = %d, want %d", len(opts.Extensions), len(wantExts))
	}
	for i, v := range wantExts {
		if opts.Extensions[i] != v {
			t.Errorf("Extensions[%d] = %q, want %q", i, opts.Extensions[i], v)
		}
	}
	if opts.Threads != 100 {
		t.Errorf("Threads = %d, want %d", opts.Threads, 100)
	}
	wantFC := []int{404, 500}
	if len(opts.FilterStatus) != len(wantFC) {
		t.Fatalf("FilterStatus length = %d, want %d", len(opts.FilterStatus), len(wantFC))
	}
	for i, v := range wantFC {
		if opts.FilterStatus[i] != v {
			t.Errorf("FilterStatus[%d] = %d, want %d", i, opts.FilterStatus[i], v)
		}
	}
	wantFS := []int{4242, 0}
	if len(opts.FilterSize) != len(wantFS) {
		t.Fatalf("FilterSize length = %d, want %d", len(opts.FilterSize), len(wantFS))
	}
	for i, v := range wantFS {
		if opts.FilterSize[i] != v {
			t.Errorf("FilterSize[%d] = %d, want %d", i, opts.FilterSize[i], v)
		}
	}
	wantMC := []int{200, 301}
	if len(opts.MatchStatus) != len(wantMC) {
		t.Fatalf("MatchStatus length = %d, want %d", len(opts.MatchStatus), len(wantMC))
	}
	for i, v := range wantMC {
		if opts.MatchStatus[i] != v {
			t.Errorf("MatchStatus[%d] = %d, want %d", i, opts.MatchStatus[i], v)
		}
	}
}

func TestParseArgs_ParamMode(t *testing.T) {
	args := []string{"param", "-u", "http://example.com/page?FUZZ=test", "-w", "/params.txt"}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Mode != "param" {
		t.Errorf("Mode = %q, want %q", opts.Mode, "param")
	}
	if opts.URL != "http://example.com/page?FUZZ=test" {
		t.Errorf("URL = %q, want %q", opts.URL, "http://example.com/page?FUZZ=test")
	}
}

func TestParseArgs_VhostModeWithHeader(t *testing.T) {
	args := []string{"vhost", "-u", "http://example.com/", "-w", "/vhosts.txt", "-H", "Host: FUZZ.example.com"}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Mode != "vhost" {
		t.Errorf("Mode = %q, want %q", opts.Mode, "vhost")
	}
	if len(opts.Headers) != 1 {
		t.Fatalf("Headers length = %d, want 1", len(opts.Headers))
	}
	if opts.Headers[0] != "Host: FUZZ.example.com" {
		t.Errorf("Headers[0] = %q, want %q", opts.Headers[0], "Host: FUZZ.example.com")
	}
}

func TestParseArgs_MissingURL(t *testing.T) {
	args := []string{"dir", "-w", "/wordlist.txt"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for missing -u, got nil")
	}
	if !strings.Contains(err.Error(), "-u") {
		t.Errorf("error message %q does not mention -u", err.Error())
	}
}

func TestParseArgs_MissingWordlist(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for missing -w, got nil")
	}
	if !strings.Contains(err.Error(), "-w") {
		t.Errorf("error message %q does not mention -w", err.Error())
	}
}

func TestParseArgs_UnknownSubcommand(t *testing.T) {
	args := []string{"spider", "-u", "http://example.com/", "-w", "/wordlist.txt"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for unknown subcommand, got nil")
	}
	if !strings.Contains(err.Error(), "spider") {
		t.Errorf("error message %q does not mention the invalid subcommand", err.Error())
	}
}

func TestParseArgs_ExtensionsCommaSeparated(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ", "-w", "/w.txt", "-e", ".asp,.aspx,.jsp"}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{".asp", ".aspx", ".jsp"}
	if len(opts.Extensions) != len(want) {
		t.Fatalf("Extensions length = %d, want %d", len(opts.Extensions), len(want))
	}
	for i, v := range want {
		if opts.Extensions[i] != v {
			t.Errorf("Extensions[%d] = %q, want %q", i, opts.Extensions[i], v)
		}
	}
}

func TestParseArgs_IntegerLists(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ", "-w", "/w.txt",
		"-fc", "403,404,500",
		"-fs", "0,1234",
		"-mc", "200,204,301,302",
	}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantFC := []int{403, 404, 500}
	if len(opts.FilterStatus) != len(wantFC) {
		t.Fatalf("FilterStatus length = %d, want %d", len(opts.FilterStatus), len(wantFC))
	}
	for i, v := range wantFC {
		if opts.FilterStatus[i] != v {
			t.Errorf("FilterStatus[%d] = %d, want %d", i, opts.FilterStatus[i], v)
		}
	}

	wantFS := []int{0, 1234}
	if len(opts.FilterSize) != len(wantFS) {
		t.Fatalf("FilterSize length = %d, want %d", len(opts.FilterSize), len(wantFS))
	}
	for i, v := range wantFS {
		if opts.FilterSize[i] != v {
			t.Errorf("FilterSize[%d] = %d, want %d", i, opts.FilterSize[i], v)
		}
	}

	wantMC := []int{200, 204, 301, 302}
	if len(opts.MatchStatus) != len(wantMC) {
		t.Fatalf("MatchStatus length = %d, want %d", len(opts.MatchStatus), len(wantMC))
	}
	for i, v := range wantMC {
		if opts.MatchStatus[i] != v {
			t.Errorf("MatchStatus[%d] = %d, want %d", i, opts.MatchStatus[i], v)
		}
	}
}

func TestParseArgs_PostMethodWithData(t *testing.T) {
	args := []string{"param", "-u", "http://example.com/login", "-w", "/params.txt",
		"-X", "POST", "-d", "username=admin&password=FUZZ",
	}
	opts, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Method != "POST" {
		t.Errorf("Method = %q, want %q", opts.Method, "POST")
	}
	if opts.Data != "username=admin&password=FUZZ" {
		t.Errorf("Data = %q, want %q", opts.Data, "username=admin&password=FUZZ")
	}
}

func TestParseArgs_EmptyArgs(t *testing.T) {
	_, err := ParseArgs([]string{})
	if err == nil {
		t.Fatal("expected error for empty args, got nil")
	}
}

func TestParseArgs_UnknownFlag(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ", "-w", "/w.txt", "-z", "unknown"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for unknown flag -z, got nil")
	}
	if !strings.Contains(err.Error(), "-z") {
		t.Errorf("error message %q does not mention the unknown flag", err.Error())
	}
}

func TestParseArgs_InvalidThreadsValue(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ", "-w", "/w.txt", "-t", "notanumber"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for invalid -t value, got nil")
	}
}

func TestParseArgs_InvalidFilterStatusValue(t *testing.T) {
	args := []string{"dir", "-u", "http://example.com/FUZZ", "-w", "/w.txt", "-fc", "abc"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for invalid -fc value, got nil")
	}
}

func TestParseArgs_FlagMissingValue(t *testing.T) {
	// -u is the last arg with no value following it
	args := []string{"dir", "-w", "/w.txt", "-u"}
	_, err := ParseArgs(args)
	if err == nil {
		t.Fatal("expected error for flag missing value, got nil")
	}
}
