package tui

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/0x6d61/pentecter/internal/agent"
)

// InputMode tracks the current input mode.
type InputMode int

const (
	ModeNormal      InputMode = iota // normal text input
	ModeSelect                       // numbered selection UI
	ModeProposal                     // y/n/e proposal approval
	ModeConfirmQuit                  // y/n quit confirmation
)

// SelectOption represents a single option in a selection UI.
type SelectOption struct {
	Label string
	Value string
}

// ipv4Re matches an IPv4 address in text.
var ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// domainRe matches a domain name with at least one dot.
var domainRe = regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)

// handleInputLine processes a line of input. Returns true if the app should quit.
func (a *App) handleInputLine(line string) bool {
	switch a.inputMode {
	case ModeConfirmQuit:
		return a.handleConfirmQuitInput(line)
	case ModeProposal:
		a.handleProposalInput(line)
		return false
	case ModeSelect:
		a.handleSelectInput(line)
		return false
	default:
		a.handleNormalInput(line)
		return false
	}
}

// handleConfirmQuitInput processes input during quit confirmation.
func (a *App) handleConfirmQuitInput(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		a.inputMode = ModeNormal
		return false
	}
}

// handleProposalInput processes input during proposal approval.
func (a *App) handleProposalInput(line string) {
	t := a.activeTarget()
	if t == nil {
		a.inputMode = ModeNormal
		return
	}

	prop := t.GetProposal()
	if prop == nil {
		a.inputMode = ModeNormal
		return
	}

	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		block := agent.NewUserInputBlock("Approved: " + prop.Description)
		a.mu.Lock()
		t.AddBlock(block)
		t.SetStatusSafe(agent.StatusRunning)
		t.ClearProposal()
		a.invalidateOutputCacheLocked()
		a.mu.Unlock()

		if ch, ok := a.agentApproveMap[t.ID]; ok {
			select {
			case ch <- true:
			default:
			}
		}

	case "n", "no":
		block := agent.NewUserInputBlock("Rejected: " + prop.Description)
		a.mu.Lock()
		t.AddBlock(block)
		t.SetStatusSafe(agent.StatusIdle)
		t.ClearProposal()
		a.invalidateOutputCacheLocked()
		a.mu.Unlock()

		if ch, ok := a.agentApproveMap[t.ID]; ok {
			select {
			case ch <- false:
			default:
			}
		}

	case "e", "edit":
		cmd := prop.Tool + " " + strings.Join(prop.Args, " ")
		a.logSystem("Edit command (copy and modify): " + cmd)

	default:
		a.logSystem("Type y (approve), n (reject), or e (edit)")
		return // stay in proposal mode
	}

	a.inputMode = ModeNormal
}

// handleSelectInput processes input during numbered selection.
func (a *App) handleSelectInput(line string) {
	line = strings.TrimSpace(line)

	if line == "q" || line == "cancel" || line == "" {
		a.inputMode = ModeNormal
		a.selectOpts = nil
		a.selectCb = nil
		return
	}

	idx, err := strconv.Atoi(line)
	if err != nil || idx < 1 || idx > len(a.selectOpts) {
		a.logSystem(fmt.Sprintf("Enter a number 1-%d, or 'q' to cancel", len(a.selectOpts)))
		return
	}

	cb := a.selectCb
	value := a.selectOpts[idx-1].Value

	// Reset state first (callback may call showSelect again)
	a.inputMode = ModeNormal
	a.selectOpts = nil
	a.selectCb = nil

	if cb != nil {
		cb(a, value)
	}
}

// handleNormalInput processes normal text input.
func (a *App) handleNormalInput(line string) {
	fullText := strings.TrimSpace(line)
	if fullText == "" {
		return
	}

	// Command routing
	if strings.HasPrefix(fullText, "/") {
		if a.handleCommand(fullText) {
			return
		}
	}

	// Target addition: IP address or /target <host>
	if host, ok := parseTargetInput(fullText); ok && a.team != nil {
		a.addTarget(host)
		return
	}

	// Natural language host extraction: "192.168.81.1をスキャンして"
	if a.team != nil && len(a.targets) == 0 {
		if host, msg, ok := extractHostFromText(fullText); ok {
			a.addTarget(host)
			if t := a.activeTarget(); t != nil {
				block := agent.NewUserInputBlock(fullText)
				a.mu.Lock()
				t.AddBlock(block)
				a.invalidateOutputCacheLocked()
				a.mu.Unlock()
			}
			if msg != "" {
				if t := a.activeTarget(); t != nil {
					if ch, ok := a.agentUserMsgMap[t.ID]; ok {
						select {
						case ch <- msg:
						default:
						}
					}
				}
			}
			return
		}
	}

	// Add as user input block
	if t := a.activeTarget(); t != nil {
		block := agent.NewUserInputBlock(fullText)
		a.mu.Lock()
		t.AddBlock(block)
		a.invalidateOutputCacheLocked()
		a.mu.Unlock()
	}

	// Send to active target's agent
	if t := a.activeTarget(); t != nil {
		if ch, ok := a.agentUserMsgMap[t.ID]; ok {
			select {
			case ch <- fullText:
			default:
			}
		}
	}
}

// parseTargetInput detects IP addresses, domain names, or /target <host>.
func parseTargetInput(text string) (string, bool) {
	if strings.HasPrefix(text, "/target ") {
		host := strings.TrimSpace(strings.TrimPrefix(text, "/target "))
		if host != "" {
			return host, true
		}
	}
	if net.ParseIP(text) != nil {
		return text, true
	}
	if domainRe.MatchString(text) && domainRe.FindString(text) == text {
		return text, true
	}
	return "", false
}

// extractHostFromText extracts an IPv4 address or domain name from natural language text.
// Returns (host, remainingMessage, found).
func extractHostFromText(text string) (string, string, bool) {
	if text == "" || strings.HasPrefix(text, "/") {
		return "", "", false
	}

	// Try IPv4 first
	match := ipv4Re.FindStringSubmatchIndex(text)
	if match != nil {
		ip := text[match[2]:match[3]]
		if net.ParseIP(ip) != nil {
			raw := text[:match[2]] + text[match[3]:]
			remaining := strings.TrimSpace(strings.Join(strings.Fields(raw), " "))
			return ip, remaining, true
		}
	}

	// Fallback: try domain name
	domainMatch := domainRe.FindStringIndex(text)
	if domainMatch != nil {
		domain := text[domainMatch[0]:domainMatch[1]]
		raw := text[:domainMatch[0]] + text[domainMatch[1]:]
		remaining := strings.TrimSpace(strings.Join(strings.Fields(raw), " "))
		return domain, remaining, true
	}

	return "", "", false
}

// addTarget adds a target to the team and updates the TUI.
func (a *App) addTarget(host string) {
	if a.team == nil {
		return
	}

	target, approveCh, userMsgCh := a.team.AddTarget(host)
	if approveCh == nil {
		return // duplicate
	}

	a.mu.Lock()
	a.targets = append(a.targets, target)
	a.agentApproveMap[target.ID] = approveCh
	a.agentUserMsgMap[target.ID] = userMsgCh
	a.selected = len(a.targets) - 1
	a.mu.Unlock()

	a.logSystem(fmt.Sprintf("Target added: %s", host))
}

// showSelect activates the numbered selection UI with a boxed display.
func (a *App) showSelect(title string, options []SelectOption, callback func(a *App, value string)) {
	a.mu.Lock()
	a.inputMode = ModeSelect
	a.selectTitle = title
	a.selectOpts = options
	a.selectIdx = 0
	a.selectCb = callback
	a.invalidateOutputCacheLocked()
	a.mu.Unlock()

	if a.testWriter != nil {
		_, _ = fmt.Fprintln(a.testWriter, title)
		for i, opt := range options {
			_, _ = fmt.Fprintf(a.testWriter, "  %d. %s\n", i+1, opt.Label)
		}
		_, _ = fmt.Fprintf(a.testWriter, "  [1-%d/q]\n", len(options))
		return
	}

	// In line-mode runtime, mode changes are not visible until we re-render.
	a.clearAndReprint()
}
