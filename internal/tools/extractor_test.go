package tools_test

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/tools"
)

func TestExtractEntities_Ports(t *testing.T) {
	lines := []string{
		"22/tcp   open  ssh     OpenSSH 8.0",
		"80/tcp   open  http    Apache httpd 2.4.49",
		"3306/udp open  mysql   MySQL 5.7",
	}

	entities := tools.ExtractEntities(lines)

	ports := filterType(entities, tools.EntityPort)
	if len(ports) != 3 {
		t.Errorf("ports: got %d, want 3", len(ports))
	}
	assertContainsValue(t, ports, "22/tcp")
	assertContainsValue(t, ports, "80/tcp")
	assertContainsValue(t, ports, "3306/udp")
}

func TestExtractEntities_CVEs(t *testing.T) {
	lines := []string{
		"[!] CVE-2021-41773: Apache 2.4.49 Path Traversal",
		"Found CVE-2021-42013 in response",
		"no vuln here",
	}

	entities := tools.ExtractEntities(lines)
	cves := filterType(entities, tools.EntityCVE)

	if len(cves) != 2 {
		t.Errorf("CVEs: got %d, want 2", len(cves))
	}
	assertContainsValue(t, cves, "CVE-2021-41773")
	assertContainsValue(t, cves, "CVE-2021-42013")
}

func TestExtractEntities_URLs(t *testing.T) {
	lines := []string{
		"+ http://10.0.0.5/admin/ (200 OK)",
		"+ https://10.0.0.5/phpmyadmin/ (200 OK)",
		"no url here",
	}

	entities := tools.ExtractEntities(lines)
	urls := filterType(entities, tools.EntityURL)

	if len(urls) != 2 {
		t.Errorf("URLs: got %d, want 2", len(urls))
	}
}

func TestExtractEntities_IPs(t *testing.T) {
	lines := []string{
		"Nmap scan report for 10.0.0.5",
		"Host is up (0.0010s latency).",
		"Gateway: 192.168.1.1",
	}

	entities := tools.ExtractEntities(lines)
	ips := filterType(entities, tools.EntityIP)

	if len(ips) < 2 {
		t.Errorf("IPs: got %d, want >= 2", len(ips))
	}
}

func TestExtractEntities_Deduplication(t *testing.T) {
	lines := []string{
		"CVE-2021-41773 found",
		"CVE-2021-41773 confirmed",
		"CVE-2021-41773 exploitable",
	}

	entities := tools.ExtractEntities(lines)
	cves := filterType(entities, tools.EntityCVE)

	if len(cves) != 1 {
		t.Errorf("duplicate CVEs should be deduplicated: got %d, want 1", len(cves))
	}
}

func filterType(entities []tools.Entity, et tools.EntityType) []tools.Entity {
	var result []tools.Entity
	for _, e := range entities {
		if e.Type == et {
			result = append(result, e)
		}
	}
	return result
}

func assertContainsValue(t *testing.T, entities []tools.Entity, value string) {
	t.Helper()
	for _, e := range entities {
		if e.Value == value {
			return
		}
	}
	t.Errorf("entity value %q not found", value)
}
