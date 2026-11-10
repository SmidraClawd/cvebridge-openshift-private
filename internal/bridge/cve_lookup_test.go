package bridge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCVECommandsAcceptSingleMultipleAndScopedQueries(t *testing.T) {
	for _, tt := range []struct{ text, command, namespace string }{
		{"CVE-2025-47273", "CVE-2025-47273", ""},
		{"cve-2025-47273 team-a", "CVE-2025-47273", "team-a"},
		{"CVE-2025-47273 CVE-2022-40897", "CVE-2022-40897,CVE-2025-47273", ""},
		{"CVE-2025-47273,CVE-2022-40897 team-a", "CVE-2022-40897,CVE-2025-47273", "team-a"},
		{"search CVE-2025-47273, CVE-2022-40897 team-a", "CVE-2022-40897,CVE-2025-47273", "team-a"},
		{"SEARCH CVE-2025-47273,cve-2025-47273", "CVE-2025-47273", ""},
		{"report team-a", "report", "team-a"},
		{"scan", "scan", ""},
		{"scan *", "scan", "*"},
		{"report *", "report", "*"},
		{"CVE-2025-47273 *", "CVE-2025-47273", "*"},
		{"HELP", "help", ""},
	} {
		t.Run(tt.text, func(t *testing.T) {
			command, ns, err := parseSlashCommand(tt.text)
			if err != nil || command != tt.command || strings.Join(ns, ",") != tt.namespace {
				t.Fatal(command, ns, err)
			}
		})
	}
	tooMany := []string{}
	for i := 0; i <= maxLookupCVEs; i++ {
		tooMany = append(tooMany, fmt.Sprintf("CVE-2026-%05d", i))
	}
	for _, text := range []string{"search", "search team-a", "CVE-2025-bad", "CVE-2025-47273 cve-2025-bad", "CVE-2025-47273 team-a team-b", "scan team-*", "scan * team-a", "CVE-2025-47273 CVE-2022-40897;", "status team-a", "scan team-a extra", strings.Join(tooMany, ",")} {
		if _, _, err := parseSlashCommand(text); err == nil {
			t.Error("invalid query accepted:", text)
		}
	}
	command, ns, err := parseSlashCommand("CVE-2025-47273 cve-tools", "cve-tools")
	if err != nil || command != "CVE-2025-47273" || !same(ns, []string{"cve-tools"}) {
		t.Fatal("an approved namespace starting with cve- must remain usable", command, ns, err)
	}
}

func lookupFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.ImageResponse = originImage(t)
	f.ImageResponse["id"] = imageDigest
	obj(f.ImageResponse["scan"])["scanTime"] = time.Now().UTC().Format(time.RFC3339Nano)
	return f
}

func TestMultiCVELookupUsesOneReadAndOnlyRequestedFindings(t *testing.T) {
	f := lookupFixture(t)
	result, err := f.App.S.Lookup(context.Background(), "cve-2025-47273,CVE-2022-40897,CVE-2025-47273", []string{"team-a"}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if f.ScanCalls != 0 || f.ImageReads != 1 || len(arr(result["rows"])) != 2 || len(stringsOf(result["cves"])) != 2 {
		t.Fatal("CVE list should share a single read-only inventory pass", f.ScanCalls, f.ImageReads, result["cves"])
	}
	for _, raw := range arr(result["rows"]) {
		row := obj(raw)
		if str(row["component"]) != "setuptools" || str(row["origin"]) != "application" || str(row["displayImage"]) != "registry.acme.test/api:latest" {
			t.Fatal("lost the package origin or deployed tag", row)
		}
		if str(row["fixedBy"]) != "65.5.1" && str(row["fixedBy"]) != "78.1.1" {
			t.Fatal("CVE target must use the individual advisory fix", row)
		}
	}
}

func TestLookupFiltersBeforeUnrelatedFindingsUseTheRowLimit(t *testing.T) {
	f := lookupFixture(t)
	vulns := []any{}
	for i := 0; i < 20001; i++ {
		vulns = append(vulns, M{"cve": fmt.Sprintf("CVE-2026-%05d", i), "severity": "IMPORTANT_VULNERABILITY_SEVERITY"})
	}
	vulns = append(vulns, M{"cve": "CVE-2025-47273", "severity": "IMPORTANT_VULNERABILITY_SEVERITY", "fixedBy": "2.0"})
	obj(f.ImageResponse["scan"])["components"] = []any{M{"name": "wanted-package", "version": "1.0", "vulns": vulns}}
	result, err := f.App.S.Lookup(context.Background(), "CVE-2025-47273", []string{"team-a"}, func() error { return nil })
	if err != nil || len(arr(result["rows"])) != 1 || boolean(result["truncated"]) {
		t.Fatal("unrelated findings consumed the search budget", err, result["truncated"])
	}
}

func TestCVECommandsPublishTablesWithoutFilesScansOrAlertState(t *testing.T) {
	for _, command := range []string{"CVE-2025-47273", "CVE-2025-47273 CVE-2022-40897", "search CVE-2025-47273,CVE-2022-40897 team-a"} {
		t.Run(command, func(t *testing.T) {
			f := lookupFixture(t)
			form := url.Values{"token": {"slash-secret"}, "command": {"/cve"}, "text": {command}, "channel_id": {channelID}, "user_id": {ownerID}}
			req := httptest.NewRequest(http.MethodPost, "/slash/cve", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			f.App.ServeHTTP(response, req)
			f.App.Wait()
			if response.Code != http.StatusOK || len(f.Posts) != 1 || f.ImageReads != 1 || f.ScanCalls != 0 || f.FileUploads != 0 {
				t.Fatal("lookup was not a single native, read-only query", response.Code, len(f.Posts), f.ImageReads, f.ScanCalls, f.FileUploads)
			}
			post := f.Posts[0]
			text := str(post["message"])
			for _, value := range []string{"team-a", "registry.acme.test/api:latest", "CVE-2025-47273", "setuptools", "65.5.0", "78.1.1", "Appens tillägg"} {
				if !strings.Contains(text, value) {
					t.Error("missing table content", value)
				}
			}
			if !strings.HasPrefix(text, "| ") || strings.Contains(text, "@channel") || len(stringsOf(post["file_ids"])) != 0 || obj(post["props"])["attachments"] != nil {
				t.Fatal("unexpected text, attachment or ping", post)
			}
			var count int
			if err := f.App.Store.DB.QueryRow("SELECT COUNT(*) FROM cve_seen").Scan(&count); err != nil || count != 0 {
				t.Fatal("search changed the alert state", count, err)
			}
		})
	}
}

func TestCVELookupRechecksScopeAndRejectsInvalidQueriesBeforeReading(t *testing.T) {
	for _, command := range []string{"CVE-2025-47273 other-team", "CVE-2025-47273 CVE-2022-bad", "CVE-2025-47273 team-a extra"} {
		f := lookupFixture(t)
		form := url.Values{"token": {"slash-secret"}, "command": {"/cve"}, "text": {command}, "channel_id": {channelID}, "user_id": {ownerID}}
		req := httptest.NewRequest(http.MethodPost, "/slash/cve", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		f.App.ServeHTTP(httptest.NewRecorder(), req)
		f.App.Wait()
		if len(f.Posts) != 0 || f.ImageReads != 0 || f.ScanCalls != 0 {
			t.Fatal("invalid or unapproved scope reached ACS", command)
		}
	}
	f := lookupFixture(t)
	f.WrongScope = true
	if _, err := f.App.S.Lookup(context.Background(), "CVE-2025-47273", []string{"team-a"}, func() error { return nil }); err == nil || f.ImageReads != 0 {
		t.Fatal("out-of-scope inventory reached image lookup")
	}
}

func TestCVELookupTablesShowNoMatchesAndMissingCoverageDifferently(t *testing.T) {
	for _, state := range []string{"complete", "partial", "failed"} {
		result := M{"kind": "lookup", "cves": []string{"CVE-2025-47273", "CVE-2022-40897"}, "namespaces": []string{"team-a"}, "totalImages": 1, "scannedImages": 1}
		switch state {
		case "partial":
			result["partialImages"] = 1
		case "failed":
			result["scannedImages"], result["failedImages"] = 0, 1
		}
		text := str(ResultMessage(result)["text"])
		for _, cve := range stringsOf(result["cves"]) {
			if !strings.Contains(text, cve) {
				t.Error("requested CVE disappeared", cve)
			}
		}
		if state == "complete" && !strings.Contains(text, "Ingen känd träff") || state == "partial" && !strings.Contains(text, "Delvis underlag") || state == "failed" && !strings.Contains(text, "Underlag saknas") {
			t.Fatal("missing coverage was presented as a negative result", state, text)
		}
	}
}

func TestCVELookupTablesDeduplicatePaginateAndSanitize(t *testing.T) {
	result := M{"kind": "lookup", "cves": []string{"CVE-2025-47273", "CVE-2022-40897"}, "namespaces": []string{"team-a"}, "totalImages": 1, "scannedImages": 1, "alertCves": []string{"CVE-2025-47273"}}
	rows := []any{}
	for i := 0; i < 40; i++ {
		row := M{"namespace": fmt.Sprintf("team-%03d", i), "image": "registry.test/api@" + imageDigest, "displayImage": "registry.test/api:v1", "imageId": imageDigest, "cve": "CVE-2025-47273", "component": "@channel <script>|package", "version": "1.0", "fixedBy": "2.0", "severity": "IMPORTANT_VULNERABILITY_SEVERITY", "origin": "base", "baseImage": "registry.test/base:1.0"}
		rows = append(rows, row, row)
	}
	rows = append(rows, M{"namespace": "hidden", "cve": "CVE-2020-99999", "component": "unrelated"})
	result["rows"] = rows
	all := ""
	for _, post := range cveLookupMessages(result) {
		text := str(post["text"])
		if utf8.RuneCountInString(text) > 16383 || post["attachments"] != nil {
			t.Fatal("unbounded lookup report")
		}
		all += text
	}
	if strings.Count(all, "`team-000`") != 1 || strings.Count(all, "＠channel") != 40 || strings.Contains(all, "@channel") || strings.Contains(all, "unrelated") || strings.Contains(all, "CVE-2020-99999") {
		t.Fatal("duplicates, unrequested data or raw mentions in lookup report")
	}
	if !strings.Contains(all, "CVE-2022-40897") || !strings.Contains(all, "Ingen känd träff") || !strings.Contains(all, "Basimage") || !strings.Contains(all, "2.0") {
		t.Fatal("missing CVE, base origin or target version")
	}
}
