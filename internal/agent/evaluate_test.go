package agent

import "testing"

func TestIsFailedOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"empty output", "", true},
		{"host down", "Nmap done: 1 IP address (0 hosts up) scanned in 1.85 seconds", true},
		{"host seems down", "Note: Host seems down.", true},
		{"connection refused", "curl: (7) Failed to connect: Connection refused", true},
		{"no route", "No route to host", true},
		{"network unreachable", "connect: Network is unreachable", true},
		{"name resolution", "Name or service not known", true},
		{"error prefix", "Error: exec failed", true},
		{"successful nmap", "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http", false},
		{"successful curl", "HTTP/1.1 200 OK\nContent-Type: text/html", false},
		{"partial output", "Starting Nmap 7.95\nSome results here", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFailedOutput(tt.output)
			if got != tt.want {
				t.Errorf("isFailedOutput(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestContainsCI(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"Hello World", "hello", true},
		{"Connection Refused", "connection refused", true},
		{"foo", "bar", false},
		{"", "", true},
		{"short", "longer string", false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.sub, func(t *testing.T) {
			got := containsCI(tt.s, tt.sub)
			if got != tt.want {
				t.Errorf("containsCI(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
			}
		})
	}
}
