package tools

import "testing"

func TestShouldLowerProcessPriority(t *testing.T) {
	tests := []struct {
		bin  string
		want bool
	}{
		{bin: "ffuf", want: true},
		{bin: "FFUF", want: true},
		{bin: "/usr/bin/ffuf", want: true},
		{bin: `C:\tools\ffuf.exe`, want: true},
		{bin: "nmap", want: false},
		{bin: "", want: false},
	}
	for _, tt := range tests {
		if got := shouldLowerProcessPriority(tt.bin); got != tt.want {
			t.Fatalf("shouldLowerProcessPriority(%q) = %v, want %v", tt.bin, got, tt.want)
		}
	}
}
