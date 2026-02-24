package webfuzz

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

// TreeUpdater allows webfuzz to update AttackDataTree without depending on agent package types.
type TreeUpdater interface {
	AddEndpointWithStatus(host string, port int, parentPath, newPath string, httpStatus int)
	AddVhost(parentHost string, port int, vhostName string)
	CompleteTask(host string, port int, path string, taskType int)
	AddParameter(host string, port int, path string, name string, paramType string)
	AddFinding(host string, port int, path string, param, category, evidence, severity string)
}

// WebfuzzTool executes webfuzz and updates AttackDataTree.
type WebfuzzTool struct {
	tree TreeUpdater
	host string
}

// NewWebfuzzTool creates a new WebfuzzTool.
func NewWebfuzzTool(tree TreeUpdater, host string) *WebfuzzTool {
	return &WebfuzzTool{tree: tree, host: host}
}

// Execute runs internal webfuzz.
func (w *WebfuzzTool) Execute(ctx context.Context, args []string, lineCh chan<- tools.OutputLine) (int, error) {
	opts, err := ParseArgs(args)
	if err != nil {
		errLine := tools.OutputLine{
			Time:    time.Now(),
			Content: fmt.Sprintf("[ERROR] %v", err),
			IsError: true,
		}
		select {
		case lineCh <- errLine:
		default:
		}
		return 1, err
	}

	basePort, basePath := extractPortAndPath(opts.URL)
	baseTreePath := normalizeTreePath(basePath)

	if w.tree != nil && opts.Mode == "dir" && baseTreePath != "/" {
		// Ensure scan root exists so discovered children are not dropped.
		baseParent := normalizeTreePath(path.Dir(baseTreePath))
		w.tree.AddEndpointWithStatus(w.host, basePort, baseParent, baseTreePath, 0)
	}

	hitFn := func(hit Hit) {
		if w.tree == nil {
			return
		}
		switch opts.Mode {
		case "dir":
			newPath := normalizeTreePath(extractPathFromHitURL(hit.URL, baseTreePath, hit.Input))
			addDirEndpointWithAncestors(w.tree, w.host, basePort, baseTreePath, newPath, hit.StatusCode)
		case "vhost":
			domain := extractDomainFromHeaders(opts.Headers)
			vhostName := hit.Input + "." + domain
			w.tree.AddVhost(w.host, basePort, vhostName)
		case "param":
			w.tree.AddParameter(w.host, basePort, baseTreePath, hit.Input, "query")
		}
	}

	lineFn := func(line string) {
		select {
		case lineCh <- tools.OutputLine{
			Time:    time.Now(),
			Content: line,
		}:
		default:
		}
	}

	if err := Run(ctx, opts, hitFn, lineFn); err != nil {
		return 1, err
	}

	if w.tree != nil {
		switch opts.Mode {
		case "dir":
			// TaskEndpointEnum = 0
			w.tree.CompleteTask(w.host, basePort, baseTreePath, 0)
		case "vhost":
			// TaskVhostDiscov = 4
			w.tree.CompleteTask(w.host, basePort, baseTreePath, 4)
		case "param":
			// TaskParamFuzz = 1
			w.tree.CompleteTask(w.host, basePort, baseTreePath, 1)
		}
	}

	return 0, nil
}

// extractPortAndPath extracts port and base path from URL template.
func extractPortAndPath(rawURL string) (int, string) {
	cleanURL := strings.ReplaceAll(rawURL, "FUZZ", "")
	cleanURL = strings.TrimRight(cleanURL, "?=&")

	parsed, err := url.Parse(cleanURL)
	if err != nil {
		return 80, "/"
	}

	port := 80
	if parsed.Port() != "" {
		var p int
		if _, err := fmt.Sscanf(parsed.Port(), "%d", &p); err == nil {
			port = p
		}
	} else if parsed.Scheme == "https" {
		port = 443
	}

	p := normalizeTreePath(parsed.Path)
	return port, p
}

// extractPathFromHitURL extracts path from a hit URL.
func extractPathFromHitURL(hitURL, parentPath, input string) string {
	parsed, err := url.Parse(hitURL)
	if err == nil && parsed.Path != "" {
		newPath := parsed.Path
		if !strings.HasPrefix(newPath, "/") {
			newPath = "/" + newPath
		}
		return newPath
	}

	newPath := path.Join(parentPath, input)
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}
	return newPath
}

// normalizeTreePath keeps path format stable for tree lookups.
func normalizeTreePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	return cleaned
}

func addDirEndpointWithAncestors(tree TreeUpdater, host string, port int, basePath string, newPath string, httpStatus int) {
	basePath = normalizeTreePath(basePath)
	newPath = normalizeTreePath(newPath)

	if isPathUnderBase(newPath, basePath) {
		baseParts := splitPathParts(basePath)
		newParts := splitPathParts(newPath)
		for ancestorLen := len(baseParts) + 1; ancestorLen < len(newParts); ancestorLen++ {
			ancestorPath := joinPathParts(newParts[:ancestorLen])
			ancestorParent := joinPathParts(newParts[:ancestorLen-1])
			tree.AddEndpointWithStatus(host, port, ancestorParent, ancestorPath, 0)
		}
	}

	parentPath := normalizeTreePath(path.Dir(newPath))
	tree.AddEndpointWithStatus(host, port, parentPath, newPath, httpStatus)
}

func isPathUnderBase(candidate string, base string) bool {
	candidate = normalizeTreePath(candidate)
	base = normalizeTreePath(base)
	if base == "/" {
		return true
	}
	if candidate == base {
		return true
	}
	return strings.HasPrefix(candidate, base+"/")
}

func splitPathParts(p string) []string {
	trimmed := strings.Trim(normalizeTreePath(p), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func joinPathParts(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

// extractDomainFromHeaders extracts domain from Host: FUZZ.<domain> header.
func extractDomainFromHeaders(headers []string) string {
	for _, h := range headers {
		if idx := strings.Index(h, "FUZZ."); idx >= 0 {
			rest := h[idx+len("FUZZ."):]
			for i, c := range rest {
				if c == '"' || c == '\'' || c == ' ' || c == '\t' {
					return rest[:i]
				}
			}
			return rest
		}
	}
	return "unknown"
}
