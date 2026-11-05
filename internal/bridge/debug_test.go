package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func debugEntries(t *testing.T, output *bytes.Buffer) []M {
	t.Helper()
	var entries []M
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var entry M
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[ACS DEBUG] ")), &entry); err != nil {
			t.Fatal("invalid debug log", err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestACSDebugShowsActualHTTPFailureWithoutLeakingCredentialsOrBodies(t *testing.T) {
	const token = "acs-secret-with-quote-\"-and-\\"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("debug logging changed the authenticated request")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "payload-private-marker") {
			t.Error("debug logging changed the request body")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "example-"+token)
		w.Header().Set("Set-Cookie", "cookie-private-marker")
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"message":"response-private-marker"}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	s := &Services{C: Config{Env: map[string]string{"STACKROX_URL": server.URL, "STACKROX_TOKEN": token, "STACKROX_STATUS_TOKEN": token}},
		Rox: server.Client(), debugLogger: log.New(&output, "", 0)}
	_, err := s.RoxRequest(context.Background(), "/v1/integrationhealth/vulndefinitions?component=SCANNER_V4&secret="+url.QueryEscape(token), "status", M{"private": "payload-private-marker"}, false)
	if err == nil || !strings.Contains(message(err), "HTTP 403") || calls.Load() != 1 {
		t.Fatal("debug logging must preserve the request result and perform exactly one request", err)
	}
	entries := debugEntries(t, &output)
	last := entries[len(entries)-1]
	if str(last["event"]) != "request_complete" || num(last["status"]) != 403 || str(last["error_kind"]) != "http" || !strings.Contains(str(last["hint"]), "Administration: Read") {
		t.Fatal("HTTP denial is missing its status or permission hint", output.String())
	}
	if str(last["endpoint"]) != server.URL+"/v1/integrationhealth/vulndefinitions" || str(last["credential"]) != "STACKROX_STATUS_TOKEN" {
		t.Fatal("request target and credential setting must be visible without query values")
	}
	for _, secret := range []string{token, url.QueryEscape(token), "payload-private-marker", "response-private-marker", "cookie-private-marker", "?component="} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("debug log leaked a credential, body, cookie or query value")
		}
	}
	if !strings.Contains(output.String(), "[REDACTED]") {
		t.Fatal("upstream header reflection must also be redacted")
	}
}

func TestACSDebugCanBeDisabledWithoutChangingRequestBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":"unchanged"}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	s := &Services{C: Config{Env: map[string]string{"LOG_LEVEL": "info", "STACKROX_URL": server.URL, "STACKROX_TOKEN": "private-token"}},
		Rox: server.Client(), debugLogger: log.New(&output, "", 0)}
	result, err := s.RoxRequest(context.Background(), "/v1/images", "read", nil, false)
	if err != nil || str(result["value"]) != "unchanged" || output.Len() != 0 {
		t.Fatal("disabling debug must retain the original result without debug output", err)
	}
}

func TestACSDebugIdentifiesTLSFailureAndRetainsVerification(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	httpClient, err := client("")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	s := &Services{C: Config{Env: map[string]string{"STACKROX_URL": server.URL, "STACKROX_TOKEN": "private-token"}},
		Rox: httpClient, debugLogger: log.New(&output, "", 0)}
	_, err = s.RoxRequest(context.Background(), "/v1/pods", "read", nil, false)
	if err == nil || calls.Load() != 0 || !strings.Contains(output.String(), "tls_unknown_authority") {
		t.Fatal("untrusted TLS must fail before sending credentials, with a diagnostic cause", err, output.String())
	}
}

func TestACSDebugExplainsInventoryAndRejectedScanResults(t *testing.T) {
	f := newFixture(t)
	defer f.Server.Close()
	f.Stale = true
	var output bytes.Buffer
	f.App.S.debugLogger = log.New(&output, "", 0)
	result, err := f.App.S.Scan(context.Background(), []string{"team-a"}, func() error { return nil }, true, false)
	if err != nil || num(result["failedImages"]) == 0 {
		t.Fatal("fixture must return a rejected stale scan", err)
	}
	for _, event := range []string{"scan_start", "inventory_complete", "image_failed", "scan_complete", "scan_time_outside_expected_range"} {
		if !strings.Contains(output.String(), event) {
			t.Fatal("missing scan diagnostic", event, output.String())
		}
	}
	for key, value := range f.App.S.C.Env {
		if strings.Contains(key, "TOKEN") && strings.Contains(output.String(), value) {
			t.Fatal("scan debug log revealed a credential")
		}
	}
}
