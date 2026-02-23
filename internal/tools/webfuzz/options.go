package webfuzz

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Options は webfuzz の実行オプション。
type Options struct {
	Mode         string        // "dir", "param", "vhost"
	URL          string        // FUZZ キーワード含む
	Wordlist     string        // ワードリストパス
	Method       string        // GET/POST (default: GET)
	Headers      []string      // -H フラグ
	Data         string        // POST body (-d)
	Extensions   []string      // -e .php,.html
	Threads      int           // -t (default: 50)
	Timeout      time.Duration // default: 10s
	FilterStatus []int         // -fc (filter codes)
	FilterSize   []int         // -fs (filter sizes)
	MatchStatus  []int         // -mc (default: 200,204,301,302,307,401,403,405)
}

// DefaultMatchStatus はデフォルトのマッチ対象ステータスコード。
var DefaultMatchStatus = []int{200, 204, 301, 302, 307, 401, 403, 405}

// validModes は有効なサブコマンド一覧。
var validModes = map[string]bool{
	"dir":   true,
	"param": true,
	"vhost": true,
}

// ParseArgs は CLI 引数をパースして Options を返す。
// args[0] はサブコマンド (dir/param/vhost)。
func ParseArgs(args []string) (Options, error) {
	if len(args) == 0 {
		return Options{}, fmt.Errorf("no arguments provided: subcommand required (dir/param/vhost)")
	}

	mode := args[0]
	if !validModes[mode] {
		return Options{}, fmt.Errorf("unknown subcommand %q: must be one of dir, param, vhost", mode)
	}

	opts := Options{
		Mode:    mode,
		Method:  "GET",
		Threads: 50,
		Timeout: 10 * time.Second,
	}

	// フラグをパース
	i := 1
	for i < len(args) {
		flag := args[i]
		if !strings.HasPrefix(flag, "-") {
			return Options{}, fmt.Errorf("unexpected argument %q: expected a flag starting with -", flag)
		}

		// 値を必要とするフラグのため、次の引数が存在するか確認
		if i+1 >= len(args) {
			return Options{}, fmt.Errorf("flag %s requires a value", flag)
		}
		value := args[i+1]
		i += 2

		switch flag {
		case "-u":
			opts.URL = value
		case "-w":
			opts.Wordlist = value
		case "-X":
			opts.Method = value
		case "-H":
			opts.Headers = append(opts.Headers, value)
		case "-d":
			opts.Data = value
		case "-e":
			opts.Extensions = strings.Split(value, ",")
		case "-t":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Options{}, fmt.Errorf("invalid value for -t: %w", err)
			}
			opts.Threads = n
		case "-fc":
			codes, err := parseIntList(value)
			if err != nil {
				return Options{}, fmt.Errorf("invalid value for -fc: %w", err)
			}
			opts.FilterStatus = codes
		case "-fs":
			sizes, err := parseIntList(value)
			if err != nil {
				return Options{}, fmt.Errorf("invalid value for -fs: %w", err)
			}
			opts.FilterSize = sizes
		case "-mc":
			codes, err := parseIntList(value)
			if err != nil {
				return Options{}, fmt.Errorf("invalid value for -mc: %w", err)
			}
			opts.MatchStatus = codes
		default:
			return Options{}, fmt.Errorf("unknown flag %s", flag)
		}
	}

	// 必須フィールドのバリデーション
	if opts.URL == "" {
		return Options{}, fmt.Errorf("-u (URL) is required")
	}
	if opts.Wordlist == "" {
		return Options{}, fmt.Errorf("-w (wordlist) is required")
	}

	// -mc が指定されなかった場合はデフォルトを使用
	if opts.MatchStatus == nil {
		opts.MatchStatus = make([]int, len(DefaultMatchStatus))
		copy(opts.MatchStatus, DefaultMatchStatus)
	}

	return opts, nil
}

// parseIntList はカンマ区切りの整数リストをパースする。
func parseIntList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %w", p, err)
		}
		result = append(result, n)
	}
	return result, nil
}
