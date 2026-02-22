package agent

import (
	"testing"
)

func Test_normalizeServiceName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"microsoft-ds", "smb"},
		{"netbios-ssn", "smb"},
		{"ms-sql-s", "mssql"},
		{"ms-sql", "mssql"},
		{"ms-wbt-server", "rdp"},
		{"domain", "dns"},
		{"pop3s", "pop3"},
		{"imaps", "imap"},
		{"smtps", "smtp"},
		{"submission", "smtp"},
		{"ssh", "ssh"},
		{"ftp", "ftp"},
		{"smb", "smb"},
		{"mysql", "mysql"},
		{"mssql", "mssql"},
		{"rdp", "rdp"},
		{"telnet", "telnet"},
		{"snmp", "snmp"},
		{"ldap", "ldap"},
		{"dns", "dns"},
		{"smtp", "smtp"},
		{"pop3", "pop3"},
		{"imap", "imap"},
		{"nfs", "nfs"},
		{"redis", "redis"},
		{"mongodb", "mongodb"},
		{"vnc", "vnc"},
		{"custom-svc", "custom-svc"},
		{"some-unknown-thing", "some-unknown-thing"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input+"_to_"+tt.want, func(t *testing.T) {
			t.Parallel()
			got := normalizeServiceName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeServiceName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func Test_GenerateChecklist_SSH(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	if cl == nil { t.Fatal("GenerateChecklist returned nil") }
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "ssh-auth-methods", "ssh-auth-methods")
	assertHasItem(t, cl, "banner-grab", "banner")
}

func Test_GenerateChecklist_FTP(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ftp", "vsftpd 3.0.3", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "anon-check", "anonymous")
	assertHasItem(t, cl, "ftp-bounce", "ftp-bounce")
}

func Test_GenerateChecklist_SMB(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("microsoft-ds", "Samba 4.9", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "enum4linux", "enum4linux")
	assertHasItem(t, cl, "smbclient", "smbclient")
	assertHasItem(t, cl, "smb-vuln", "smb-vuln")
}

func Test_GenerateChecklist_MySQL(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("mysql", "MySQL 5.7", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "mysql-info", "mysql-info")
	assertHasItem(t, cl, "default-creds", "default")
}

func Test_GenerateChecklist_MSSQL(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ms-sql-s", "Microsoft SQL Server 2019", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "mssqlclient", "mssqlclient")
	assertHasItem(t, cl, "default-creds", "sa")
}

func Test_GenerateChecklist_PostgreSQL(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("postgresql", "PostgreSQL 13", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "pg-ready", "pg_isready")
	assertHasItem(t, cl, "default-creds", "psql")
}

func Test_GenerateChecklist_RDP(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ms-wbt-server", "Microsoft Terminal Services", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "rdp-enum", "rdp-enum-encryption")
}

func Test_GenerateChecklist_Telnet(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("telnet", "", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "banner-grab", "telnet")
}

func Test_GenerateChecklist_SNMP(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("snmp", "SNMPv2", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "snmpwalk", "snmpwalk")
}

func Test_GenerateChecklist_LDAP(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ldap", "OpenLDAP 2.4", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "ldapsearch", "ldapsearch")
	assertHasItem(t, cl, "ldap-rootdse", "ldap-rootdse")
}

func Test_GenerateChecklist_DNS(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("domain", "BIND 9.11", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "zone-transfer", "axfr")
	assertHasItem(t, cl, "dns-enum", "dnsenum")
}

func Test_GenerateChecklist_SMTP(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("smtp", "Postfix", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "smtp-user-enum", "smtp-user-enum")
	assertHasItem(t, cl, "vrfy", "vrfy")
}

func Test_GenerateChecklist_POP3(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("pop3", "Dovecot", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "banner-grab", "pop3")
}

func Test_GenerateChecklist_IMAP(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("imap", "Dovecot", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "banner-grab", "imap")
}

func Test_GenerateChecklist_NFS(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("nfs", "", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "showmount", "showmount")
}

func Test_GenerateChecklist_Redis(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("redis", "Redis 6.0", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "redis-cli", "redis-cli")
}

func Test_GenerateChecklist_MongoDB(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("mongodb", "MongoDB 4.4", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "mongo-connect", "mongo")
}

func Test_GenerateChecklist_VNC(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("vnc", "RealVNC 5", true)
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "vnc-info", "vnc-info")
}

func Test_GenerateChecklist_NoKnowledge(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", false)
	for _, item := range cl.Items {
		if item.ID == "search-knowledge" {
			t.Error("search-knowledge should NOT be present when hasKnowledge=false")
		}
	}
}

func Test_GenerateChecklist_WithKnowledge(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	assertHasItem(t, cl, "search-knowledge", "search_knowledge")
}

func Test_GenerateChecklist_UnknownService(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("custom-weird-svc", "1.0", true)
	if len(cl.Items) != 2 {
		t.Errorf("unknown service should have 2 items, got %d", len(cl.Items))
	}
	assertHasItem(t, cl, "searchsploit", "searchsploit")
	assertHasItem(t, cl, "search-knowledge", "search_knowledge")
}

func Test_GenerateChecklist_EmptyVersion(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "", true)
	if cl == nil { t.Fatal("returned nil for empty version") }
	if len(cl.Items) == 0 { t.Error("checklist should not be empty") }
	for _, item := range cl.Items {
		if item.ID == "searchsploit" {
			last := item.Description[len(item.Description)-1]
			if last == ' ' {
				t.Errorf("searchsploit description has trailing space: %q", item.Description)
			}
		}
	}
}

func Test_UpdateChecklistCompletion_Match(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	UpdateChecklistCompletion(cl, []string{"searchsploit ssh OpenSSH 8.2"})
	item := findItem(cl, "searchsploit")
	if item == nil { t.Fatal("searchsploit item not found") }
	if !item.Done { t.Error("searchsploit should be Done") }
}

func Test_UpdateChecklistCompletion_CaseInsensitive(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	UpdateChecklistCompletion(cl, []string{"SEARCHSPLOIT SSH OpenSSH 8.2"})
	item := findItem(cl, "searchsploit")
	if item == nil { t.Fatal("not found") }
	if !item.Done { t.Error("case-insensitive match should mark Done") }
}

func Test_UpdateChecklistCompletion_MultipleMatch(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	UpdateChecklistCompletion(cl, []string{
		"searchsploit ssh OpenSSH 8.2",
		"nmap --script ssh-auth-methods -p 22 target",
	})
	si := findItem(cl, "searchsploit")
	if si == nil || !si.Done { t.Error("searchsploit should be Done") }
	ai := findItem(cl, "ssh-auth-methods")
	if ai == nil || !ai.Done { t.Error("ssh-auth-methods should be Done") }
}

func Test_UpdateChecklistCompletion_NoMatch(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	UpdateChecklistCompletion(cl, []string{"ls -la /tmp", "cat /etc/passwd"})
	for _, item := range cl.Items {
		if item.Done { t.Errorf("item %q should not be Done", item.ID) }
	}
}

func Test_UpdateChecklistCompletion_AdditiveOnly(t *testing.T) {
	t.Parallel()
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", true)
	UpdateChecklistCompletion(cl, []string{"searchsploit ssh OpenSSH 8.2"})
	item := findItem(cl, "searchsploit")
	if item == nil || !item.Done { t.Fatal("should be Done") }
	UpdateChecklistCompletion(cl, []string{})
	item = findItem(cl, "searchsploit")
	if !item.Done { t.Error("Done should never go back to false") }
}

func Test_ChecklistAllDone_AllDone(t *testing.T) {
	t.Parallel()
	cl := &ServiceChecklist{Items: []ChecklistItem{
		{ID: "a", Done: true}, {ID: "b", Done: true}, {ID: "c", Done: true},
	}}
	if !ChecklistAllDone(cl) { t.Error("expected AllDone=true") }
}

func Test_ChecklistAllDone_NotAllDone(t *testing.T) {
	t.Parallel()
	cl := &ServiceChecklist{Items: []ChecklistItem{
		{ID: "a", Done: true}, {ID: "b", Done: false}, {ID: "c", Done: true},
	}}
	if ChecklistAllDone(cl) { t.Error("expected AllDone=false") }
}

func Test_ChecklistAllDone_EmptyList(t *testing.T) {
	t.Parallel()
	cl := &ServiceChecklist{Items: []ChecklistItem{}}
	if !ChecklistAllDone(cl) { t.Error("expected AllDone=true for empty list") }
}

// Test helpers

func assertHasItem(t *testing.T, cl *ServiceChecklist, id, keywordSubstr string) {
	t.Helper()
	if cl == nil { t.Fatalf("checklist is nil, expected item %q", id); return }
	for _, item := range cl.Items {
		if item.ID == id {
			for _, kw := range item.Keywords {
				if testContainsLower(kw, keywordSubstr) { return }
			}
			if testContainsLower(item.Description, keywordSubstr) { return }
			t.Errorf("item %q: no keyword/desc contains %q (kw=%v, desc=%q)",
				id, keywordSubstr, item.Keywords, item.Description)
			return
		}
	}
	t.Errorf("item %q not found in checklist (have %v)", id, itemIDs(cl))
}

func findItem(cl *ServiceChecklist, id string) *ChecklistItem {
	for i := range cl.Items {
		if cl.Items[i].ID == id { return &cl.Items[i] }
	}
	return nil
}

func itemIDs(cl *ServiceChecklist) []string {
	ids := make([]string, 0, len(cl.Items))
	for _, item := range cl.Items { ids = append(ids, item.ID) }
	return ids
}

func testContainsLower(s, substr string) bool {
	if len(s) == 0 || len(substr) == 0 { return false }
	sl := testToLower(s)
	subl := testToLower(substr)
	for i := 0; i <= len(sl)-len(subl); i++ {
		if sl[i:i+len(subl)] == subl { return true }
	}
	return false
}

func testToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' { c += 'a' - 'A' }
		b[i] = c
	}
	return string(b)
}
