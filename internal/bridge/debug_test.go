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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func debugEntries(t *testing.T, output *bytes.Buffer) []M {
	t.Helper()
	var entries []M
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var entry M
		_, body, ok := strings.Cut(line, "] ")
		if !ok {
			t.Fatal("invalid log prefix", line)
		}
		if err := json.Unmarshal([]byte(body), &entry); err != nil {
			t.Fatal("invalid debug log", err)
		}
		entries = append(entries, entry)
	}
	return entries
}

// A log event lets startup tests wait for actual loop work without forcing a
// tick, sleeping for the hourly interval, or reading a buffer concurrently.
type monitorLogCapture struct {
	mu     sync.Mutex
	output bytes.Buffer
	event  string
	done   chan struct{}
}

func (c *monitorLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.output.Write(p)
	if strings.Contains(string(p), `"event":"`+c.event+`"`) {
		select {
		case c.done <- struct{}{}:
		default:
		}
	}
	return n, err
}

func runMonitorLoop(t *testing.T, f *monitorFixture, event string) *bytes.Buffer {
	t.Helper()
	capture := &monitorLogCapture{event: event, done: make(chan struct{}, 1)}
	f.app.S.debugLogger = log.New(capture, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	f.app.ctx = ctx
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.app.Loop()
	}()
	defer func() {
		cancel()
		<-done
		f.app.Wait()
	}()
	select {
	case <-capture.done:
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not reach", event)
	}
	// Stop the loop and wait for the monitor before inspecting logs or fixtures.
	cancel()
	<-done
	f.app.Wait()
	return &capture.output
}

func TestDatabaseMonitorStartupChecksImmediatelyAndLogsAtInfo(t *testing.T) {
	for _, code := range []int{200, 403} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := newMonitorFixture(t)
			f.stamp, f.statusCode = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), code
			f.app.S.C.Env["LOG_LEVEL"] = "info"
			output := runMonitorLoop(t, f, "monitor_check_complete")
			if f.checks != 1 || len(f.posts) != 1 {
				t.Fatal("startup must check ACS once and deliver without a slash command", f.checks, len(f.posts))
			}
			entries := debugEntries(t, output)
			startup := entries[0]
			if str(startup["event"]) != "monitor_startup" || !boolean(startup["enabled"]) || boolean(startup["debug_enabled"]) || str(startup["next_check"]) != "immediate" {
				t.Fatal("startup must explain monitor enablement even with debug disabled", output.String())
			}
			for _, event := range []string{"monitor_check_start", "monitor_acs_start", "monitor_acs_complete", "monitor_post_sent", "monitor_check_complete"} {
				if !strings.Contains(output.String(), `"event":"`+event+`"`) {
					t.Fatal("missing startup diagnostic", event, output.String())
				}
			}
			if code == 403 && (!strings.Contains(output.String(), "HTTP 403") || !strings.Contains(output.String(), `"state":"unknown"`)) {
				t.Fatal("an ACS denial must be visible at info level", output.String())
			}
			if strings.Contains(output.String(), "[ACS DEBUG]") {
				t.Fatal("info logging must not enable request debug")
			}
			for key, value := range f.app.S.C.Env {
				if strings.Contains(key, "TOKEN") && value != "" && strings.Contains(output.String(), value) {
					t.Fatal("startup log revealed a credential")
				}
			}
		})
	}
}

func TestDatabaseMonitorStartupExplainsDisabledMonitorWithoutContactingACS(t *testing.T) {
	f := newMonitorFixture(t)
	f.app.S.C.Env["DATABASE_MONITOR_CHANNEL_ID"] = ""
	f.app.S.C.Env["LOG_LEVEL"] = "info"
	output := runMonitorLoop(t, f, "monitor_startup")
	if f.checks != 0 || len(f.posts) != 0 || !strings.Contains(output.String(), `"enabled":false`) || !strings.Contains(output.String(), "DATABASE_MONITOR_CHANNEL_ID") {
		t.Fatal("disabled monitor must explain the missing setting without making requests", output.String())
	}
}

func TestDatabaseMonitorRestartLogsCheckAndSuppressedPost(t *testing.T) {
	f := newMonitorFixture(t)
	now := time.Now().UTC()
	f.stamp = now.Add(-time.Hour).Format(time.RFC3339)
	if err := f.app.checkDatabaseMonitor(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	// A new process uses the notification state already saved on the PVC.
	f.app = NewApp(context.Background(), f.app.S, f.app.Store)
	output := runMonitorLoop(t, f, "monitor_post_skipped")
	if f.checks != 2 || len(f.posts) != 1 || !strings.Contains(output.String(), "unchanged_within_24_hours") || !strings.Contains(output.String(), "monitor_acs_complete") {
		t.Fatal("restart must recheck ACS, retain deduplication and explain why no post is sent", output.String())
	}
}

func TestDatabaseMonitorLogsFailureStageAndRetry(t *testing.T) {
	for _, tt := range []struct {
		stage  string
		mutate func(*monitorFixture)
	}{
		{"state_read", func(f *monitorFixture) { _ = f.app.Store.Close() }},
		{"mattermost_destination", func(f *monitorFixture) { f.public = true }},
		{"mattermost_post", func(f *monitorFixture) { f.postCode = 403 }},
	} {
		t.Run(tt.stage, func(t *testing.T) {
			f := newMonitorFixture(t)
			f.stamp = time.Now().UTC().Format(time.RFC3339)
			f.app.S.C.Env["LOG_LEVEL"] = "info"
			tt.mutate(f)
			var output bytes.Buffer
			f.app.S.debugLogger = log.New(&output, "", 0)
			f.app.startDatabaseMonitor(time.Now())
			f.app.Wait()
			if !strings.Contains(output.String(), `"stage":"`+tt.stage+`"`) || !strings.Contains(output.String(), `"event":"monitor_retry_scheduled"`) {
				t.Fatal("monitor failure must identify its stage and retry", output.String())
			}
			if tt.stage == "state_read" && (strings.Contains(output.String(), "sql:") || strings.Contains(output.String(), "state.sqlite3")) {
				t.Fatal("storage errors must not dump SQL details")
			}
			if tt.stage == "mattermost_post" && !strings.Contains(output.String(), "HTTP 403") {
				t.Fatal("Mattermost delivery denial must be visible", output.String())
			}
		})
	}
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
