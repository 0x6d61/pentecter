package tools

import (
	"strings"
)

func shouldLowerProcessPriority(binary string) bool {
	if binary == "" {
		return false
	}
	b := strings.TrimSpace(strings.ToLower(binary))
	if i := strings.LastIndexAny(b, `/\`); i >= 0 && i+1 < len(b) {
		b = b[i+1:]
	}
	b = strings.TrimSuffix(b, ".exe")
	return b == "ffuf"
}
