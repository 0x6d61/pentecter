package tools_test

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/tools"
)

func TestBlacklist_Match_BlocksDangerousCommands(t *testing.T) {
	bl := tools.NewBlacklist([]string{
		`rm\s+-rf\s+/`,
		`dd\s+if=`,
		`mkfs`,
		`shutdown`,
	})

	cases := []struct {
		command string
		blocked bool
	}{
		{"rm -rf /", true},
		{"rm -rf /tmp/test", true},
		{"dd if=/dev/zero of=/dev/sda", true},
		{"mkfs.ext4 /dev/sdb", true},
		{"shutdown -h now", true},
		{"nmap -sV 10.0.0.5", false},
		{"nikto -h http://10.0.0.5/", false},
		{"curl -si http://10.0.0.5/", false},
	}

	for _, c := range cases {
		got := bl.Match(c.command)
		if got != c.blocked {
			t.Errorf("Match(%q): got %v, want %v", c.command, got, c.blocked)
		}
	}
}

func TestBlacklist_EmptyPatterns_NeverBlocks(t *testing.T) {
	bl := tools.NewBlacklist(nil)
	if bl.Match("rm -rf /") {
		t.Error("empty blacklist should not block anything")
	}
}
