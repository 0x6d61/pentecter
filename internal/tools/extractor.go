package tools

import (
	"regexp"
	"strings"
)

// universalPatterns はツール種別を問わず通用する汎用抽出パターン。
// パーサーではなく「見つかれば拾う」greedy な抽出。
var universalPatterns = []struct {
	typ     EntityType
	pattern *regexp.Regexp
}{
	{
		EntityPort,
		regexp.MustCompile(`\b(\d{1,5}/(tcp|udp))\s+open`),
	},
	{
		EntityCVE,
		regexp.MustCompile(`\b(CVE-\d{4}-\d{4,})\b`),
	},
	{
		EntityURL,
		regexp.MustCompile(`https?://[^\s"'<>]+`),
	},
	{
		EntityIP,
		// プライベート + グローバル IP を広く拾う（ループバックは除外）
		regexp.MustCompile(`\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b`),
	},
}

// loopbackPrefixes はEntity抽出で除外するIPプレフィックス。
var loopbackPrefixes = []string{"127.", "0.0.0.0"}

// ExtractEntities は lines から全ユニバーサルパターンに一致する Entity を抽出し、
// 重複を除いて返す。順序は出現順。
func ExtractEntities(lines []string) []Entity {
	seen := make(map[string]bool)
	var result []Entity

	for _, line := range lines {
		for _, p := range universalPatterns {
			matches := p.pattern.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				// サブグループがある場合は m[1]、ない場合は m[0] を値とする。
				val := m[0]
				if len(m) > 1 && m[1] != "" {
					val = m[1]
				}

				// IPのループバック除外
				if p.typ == EntityIP && isLoopback(val) {
					continue
				}

				key := string(p.typ) + ":" + val
				if seen[key] {
					continue
				}
				seen[key] = true

				result = append(result, Entity{
					Type:    p.typ,
					Value:   val,
					Context: strings.TrimSpace(line),
				})
			}
		}
	}

	return result
}

func isLoopback(ip string) bool {
	for _, prefix := range loopbackPrefixes {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}
