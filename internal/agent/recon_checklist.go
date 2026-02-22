package agent

import (
	"fmt"
	"strings"
)

// ChecklistItem represents a single recon task for a service.
type ChecklistItem struct {
	ID          string   `json:"id"`          // e.g. "searchsploit", "anon-check"
	Description string   `json:"description"` // Prompt display text
	Keywords    []string `json:"keywords"`    // AND-match against command history
	Done        bool     `json:"done"`        // additive-only: once true, never goes back
}

// ServiceChecklist holds the recon checklist for a specific service.
type ServiceChecklist struct {
	Items []ChecklistItem `json:"items"`
}

// serviceAliases maps nmap service names to canonical names.
var serviceAliases = map[string]string{
	"microsoft-ds": "smb",
	"netbios-ssn":  "smb",
	"ms-sql-s":     "mssql",
	"ms-sql":       "mssql",
	"ms-wbt-server": "rdp",
	"domain":       "dns",
	"pop3s":        "pop3",
	"imaps":        "imap",
	"smtps":        "smtp",
	"submission":   "smtp",
}

// normalizeServiceName maps nmap service aliases to canonical names.
func normalizeServiceName(service string) string {
	if canonical, ok := serviceAliases[service]; ok {
		return canonical
	}
	return service
}

// GenerateChecklist creates a deterministic recon checklist for the given service.
func GenerateChecklist(service, version string, hasKnowledge bool) *ServiceChecklist {
	svc := normalizeServiceName(service)
	items := []ChecklistItem{}

	// Common: searchsploit
	searchDesc := fmt.Sprintf("searchsploit %s", svc)
	searchKeywords := []string{"searchsploit", svc}
	if version != "" {
		searchDesc = fmt.Sprintf("searchsploit %s %s", svc, version)
	}
	items = append(items, ChecklistItem{ID: "searchsploit", Description: searchDesc, Keywords: searchKeywords})

	if hasKnowledge {
		items = append(items, ChecklistItem{
			ID: "search-knowledge", Description: fmt.Sprintf("search_knowledge %s", svc),
			Keywords: []string{"search_knowledge", svc},
		})
	}

	switch svc {
	case "ftp":
		items = append(items,
			ChecklistItem{ID: "anon-check", Description: "Check FTP anonymous login", Keywords: []string{"ftp", "anonymous"}},
			ChecklistItem{ID: "ftp-bounce", Description: "Check FTP bounce attack", Keywords: []string{"ftp-bounce"}},
		)
	case "ssh":
		items = append(items,
			ChecklistItem{ID: "ssh-auth-methods", Description: "Enumerate SSH auth methods", Keywords: []string{"ssh-auth-methods"}},
			ChecklistItem{ID: "banner-grab", Description: "SSH banner grab", Keywords: []string{"ssh", "banner"}},
		)
	case "smb":
		items = append(items,
			ChecklistItem{ID: "enum4linux", Description: "Run enum4linux for SMB enumeration", Keywords: []string{"enum4linux"}},
			ChecklistItem{ID: "smbclient", Description: "List SMB shares with smbclient", Keywords: []string{"smbclient"}},
			ChecklistItem{ID: "smb-vuln", Description: "Run nmap smb-vuln scripts", Keywords: []string{"smb-vuln"}},
		)
	case "mysql":
		items = append(items,
			ChecklistItem{ID: "mysql-info", Description: "Run nmap mysql-info script", Keywords: []string{"mysql-info"}},
			ChecklistItem{ID: "default-creds", Description: "Try MySQL default credentials", Keywords: []string{"mysql", "-u"}},
		)
	case "mssql":
		items = append(items,
			ChecklistItem{ID: "mssqlclient", Description: "Try impacket-mssqlclient connection", Keywords: []string{"mssqlclient"}},
			ChecklistItem{ID: "default-creds", Description: "Try MSSQL default credentials (sa account)", Keywords: []string{"mssql", "sa"}},
		)
	case "postgresql":
		items = append(items,
			ChecklistItem{ID: "pg-ready", Description: "Check PostgreSQL availability with pg_isready", Keywords: []string{"pg_isready"}},
			ChecklistItem{ID: "default-creds", Description: "Try PostgreSQL default credentials with psql", Keywords: []string{"psql", "-u"}},
		)
	case "rdp":
		items = append(items,
			ChecklistItem{ID: "rdp-enum", Description: "Enumerate RDP encryption (nmap rdp-enum-encryption)", Keywords: []string{"rdp-enum-encryption"}},
		)
	case "telnet":
		items = append(items,
			ChecklistItem{ID: "banner-grab", Description: "Telnet banner grab", Keywords: []string{"telnet", "banner"}},
		)
	case "snmp":
		items = append(items,
			ChecklistItem{ID: "snmpwalk", Description: "SNMP walk with community strings", Keywords: []string{"snmpwalk"}},
		)
	case "ldap":
		items = append(items,
			ChecklistItem{ID: "ldapsearch", Description: "LDAP search for base information", Keywords: []string{"ldapsearch"}},
			ChecklistItem{ID: "ldap-rootdse", Description: "Enumerate LDAP rootDSE", Keywords: []string{"ldap-rootdse"}},
		)
	case "dns":
		items = append(items,
			ChecklistItem{ID: "zone-transfer", Description: "Attempt DNS zone transfer (dig axfr)", Keywords: []string{"dig", "axfr"}},
			ChecklistItem{ID: "dns-enum", Description: "DNS enumeration (dnsenum or dnsrecon)", Keywords: []string{"dnsenum"}},
		)
	case "smtp":
		items = append(items,
			ChecklistItem{ID: "smtp-user-enum", Description: "SMTP user enumeration", Keywords: []string{"smtp-user-enum"}},
			ChecklistItem{ID: "vrfy", Description: "SMTP VRFY command check", Keywords: []string{"smtp", "vrfy"}},
		)
	case "pop3":
		items = append(items,
			ChecklistItem{ID: "banner-grab", Description: "POP3 banner grab", Keywords: []string{"pop3"}},
		)
	case "imap":
		items = append(items,
			ChecklistItem{ID: "banner-grab", Description: "IMAP banner grab", Keywords: []string{"imap"}},
		)
	case "nfs":
		items = append(items,
			ChecklistItem{ID: "showmount", Description: "List NFS exports (showmount)", Keywords: []string{"showmount"}},
		)
	case "redis":
		items = append(items,
			ChecklistItem{ID: "redis-cli", Description: "Redis server info (redis-cli info)", Keywords: []string{"redis-cli"}},
		)
	case "mongodb":
		items = append(items,
			ChecklistItem{ID: "mongo-connect", Description: "Try MongoDB unauthenticated connection", Keywords: []string{"mongo"}},
		)
	case "vnc":
		items = append(items,
			ChecklistItem{ID: "vnc-info", Description: "VNC server info (nmap vnc-info)", Keywords: []string{"vnc-info"}},
		)
	}

	return &ServiceChecklist{Items: items}
}

// UpdateChecklistCompletion checks commands against checklist items.
// For each item, if ALL keywords are found (case-insensitive substring match)
// in ANY single command, mark Done=true. Once Done=true, it never reverts to false.
func UpdateChecklistCompletion(checklist *ServiceChecklist, commands []string) {
	for i := range checklist.Items {
		if checklist.Items[i].Done {
			continue // additive-only: skip already done items
		}
		for _, cmd := range commands {
			if matchesAllKeywords(cmd, checklist.Items[i].Keywords) {
				checklist.Items[i].Done = true
				break
			}
		}
	}
}

// matchesAllKeywords returns true if all keywords are found as case-insensitive substrings.
func matchesAllKeywords(cmd string, keywords []string) bool {
	lower := strings.ToLower(cmd)
	for _, kw := range keywords {
		if !strings.Contains(lower, kw) {
			return false
		}
	}
	return true
}

// ChecklistAllDone returns true if all items are Done (empty = true).
func ChecklistAllDone(checklist *ServiceChecklist) bool {
	for _, item := range checklist.Items {
		if !item.Done {
			return false
		}
	}
	return true
}
