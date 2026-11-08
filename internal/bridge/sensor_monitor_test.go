package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func sensorFixture(t *testing.T, now time.Time) *monitorFixture {
	t.Helper()
	f := newMonitorFixture(t)
	f.app.S.C.Env["SENSOR_MONITOR_ENABLED"] = "true"
	f.stamp = now.Add(-time.Hour).Format(time.RFC3339)
	f.sensorReply = M{"cluster": M{"id": "cluster-123", "name": "labb",
		"healthStatus": M{"lastContact": now.Format(time.RFC3339)},
		"status":       M{"certExpiryStatus": M{"sensorCertExpiry": "private-cert-marker"}}}}
	return f
}

func TestSensorStatusUsesSelectedClusterAndHandlesMissingEvidence(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name, stamp, state string
		code               int
		legacy, wrongID    bool
	}{
		{name: "fresh", stamp: now.Add(-time.Minute).Format(time.RFC3339), state: "connected"},
		{name: "at limit", stamp: now.Add(-10 * time.Minute).Format(time.RFC3339), state: "connected"},
		{name: "old", stamp: now.Add(-11 * time.Minute).Format(time.RFC3339), state: "missing"},
		{name: "legacy", stamp: now.Add(-time.Minute).Format(time.RFC3339), state: "connected", legacy: true},
		{name: "empty", state: "unknown"},
		{name: "invalid", stamp: "not-a-time", state: "unknown"},
		{name: "future", stamp: now.Add(2 * time.Minute).Format(time.RFC3339), state: "unknown"},
		{name: "clock tolerance", stamp: now.Add(30 * time.Second).Format(time.RFC3339), state: "connected"},
		{name: "forbidden is not disconnected", stamp: now.Format(time.RFC3339), state: "unknown", code: 403},
		{name: "not found", state: "unknown", code: 404},
		{name: "unavailable", state: "unknown", code: 503},
		{name: "wrong cluster", stamp: now.Format(time.RFC3339), state: "unknown", wrongID: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := sensorFixture(t, now)
			cluster := obj(f.sensorReply["cluster"])
			cluster["healthStatus"] = M{"lastContact": tt.stamp}
			if tt.legacy {
				cluster["healthStatus"] = M{}
				cluster["status"] = M{"lastContact": tt.stamp}
			}
			if tt.wrongID {
				cluster["id"] = "other-cluster"
			}
			f.sensorCode = tt.code
			r := f.app.S.sensorStatusAt(context.Background(), now)
			if str(r["state"]) != tt.state || f.sensorChecks != 1 {
				t.Fatal(r, f.sensorChecks)
			}
			if tt.state == "unknown" && (str(r["reason"]) == "" || str(r["lastContact"]) != "") {
				t.Fatal("unknown contact must explain missing evidence", r)
			}
			if strings.Contains(encode(r), "private-cert-marker") {
				t.Fatal("certificate data must not enter the sensor result")
			}
		})
	}
	// Do not hide a malformed modern field with an apparently healthy old value.
	f := sensorFixture(t, now)
	cluster := obj(f.sensorReply["cluster"])
	cluster["healthStatus"] = M{"lastContact": "invalid"}
	cluster["status"] = M{"lastContact": now.Format(time.RFC3339)}
	if r := f.app.S.sensorStatusAt(context.Background(), now); str(r["state"]) != "unknown" {
		t.Fatal(r)
	}
}

func TestSensorMonitorTransitionsPersistAcrossRestartAndRemainSeparateFromDatabase(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	f := sensorFixture(t, now)
	check := func(when time.Time, want int) {
		t.Helper()
		if err := f.app.checkSensorMonitor(context.Background(), when); err != nil {
			t.Fatal(err)
		}
		if len(f.posts) != want {
			t.Fatalf("got %d posts at %s, want %d", len(f.posts), when, want)
		}
	}
	check(now, 1)
	check(now.Add(5*time.Minute), 1)
	var seq int
	var name, path string
	if err := f.app.Store.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	f.app = NewApp(context.Background(), f.app.S, store)
	check(now.Add(5*time.Minute), 1)
	check(now.Add(15*time.Minute), 2)
	check(now.Add(20*time.Minute), 2)
	if !strings.Contains(encode(f.posts[1]), "Kontakt saknas") {
		t.Fatal(f.posts[1])
	}
	obj(f.sensorReply["cluster"])["healthStatus"] = M{"lastContact": now.Add(25 * time.Minute).Format(time.RFC3339)}
	check(now.Add(25*time.Minute), 3)
	if !strings.Contains(encode(f.posts[2]), "Kontakt återställd") {
		t.Fatal(f.posts[2])
	}
	f.sensorCode = 403
	check(now.Add(30*time.Minute), 4)
	if text := encode(f.posts[3]); !strings.Contains(text, "HTTP 403") || strings.Contains(text, "Kontakt saknas") {
		t.Fatal(text)
	}
	check(now.Add(35*time.Minute), 4)
	f.sensorCode = 200
	obj(f.sensorReply["cluster"])["healthStatus"] = M{"lastContact": now.Add(40 * time.Minute).Format(time.RFC3339)}
	check(now.Add(40*time.Minute), 5)
	if text := encode(f.posts[4]); !strings.Contains(text, "verifieras igen") || strings.Contains(text, "Kontakt återställd") {
		t.Fatal(text)
	}
	obj(f.sensorReply["cluster"])["healthStatus"] = M{"lastContact": now.Add(24*time.Hour + 40*time.Minute).Format(time.RFC3339)}
	check(now.Add(24*time.Hour+40*time.Minute), 6)
	var count int
	if err := f.app.Store.DB.QueryRow("SELECT count(*) FROM database_monitor").Scan(&count); err != nil || count != 0 {
		t.Fatal("sensor state polluted database monitor", count, err)
	}
	for _, post := range f.posts {
		text := encode(post)
		for _, secret := range []string{"@channel", "private-cert-marker", "rox-read", f.server.URL} {
			if strings.Contains(text, secret) {
				t.Fatal("unexpected data in notice", secret)
			}
		}
	}
}

func TestSensorMonitorRetriesDeliveryAndRejectsWrongChannel(t *testing.T) {
	for _, mode := range []string{"post error", "missing acknowledgement", "public channel", "removed bot"} {
		t.Run(mode, func(t *testing.T) {
			f := sensorFixture(t, time.Now().UTC())
			switch mode {
			case "post error":
				f.postCode = 503
			case "missing acknowledgement":
				f.badAck = true
			case "public channel":
				f.public = true
			case "removed bot":
				f.wrongMember = true
			}
			if err := f.app.checkSensorMonitor(context.Background(), time.Now()); err == nil {
				t.Fatal("invalid delivery accepted")
			}
			var count int
			if err := f.app.Store.DB.QueryRow("SELECT count(*) FROM sensor_monitor").Scan(&count); err != nil || count != 0 {
				t.Fatal(count, err)
			}
			f.postCode, f.badAck, f.public, f.wrongMember = 201, false, false, false
			if err := f.app.checkSensorMonitor(context.Background(), time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSensorMonitorCadenceDisabledAndIndependentWorkers(t *testing.T) {
	now := time.Now().UTC()
	f := sensorFixture(t, now)
	f.app.worker.Lock()
	defer f.app.worker.Unlock()
	f.app.monitor.Lock()
	defer f.app.monitor.Unlock()
	f.app.startSensorMonitor(now)
	f.app.Wait()
	f.app.startSensorMonitor(now.Add(4 * time.Minute))
	f.app.Wait()
	if f.sensorChecks != 1 || len(f.posts) != 1 {
		t.Fatal("sensor worker blocked or polled too frequently", f.sensorChecks)
	}
	f.app.startSensorMonitor(now.Add(5 * time.Minute))
	f.app.Wait()
	if f.sensorChecks != 2 || len(f.posts) != 1 {
		t.Fatal(f.sensorChecks, len(f.posts))
	}
	f.app.S.C.Env["SENSOR_MONITOR_ENABLED"] = "false"
	f.app.startSensorMonitor(now.Add(10 * time.Minute))
	f.app.Wait()
	if f.sensorChecks != 2 {
		t.Fatal("disabled worker contacted Central")
	}
	f.app.S.C.Env["SENSOR_MONITOR_ENABLED"] = "true"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.app.ctx = ctx
	f.app.startSensorMonitor(now.Add(15 * time.Minute))
	f.app.Wait()
	if f.sensorChecks != 2 {
		t.Fatal("cancelled worker contacted Central")
	}
}

func TestSensorMonitorStartupLogsAtInfoAndMakesImmediateRequest(t *testing.T) {
	f := sensorFixture(t, time.Now().UTC())
	f.app.S.C.Env["LOG_LEVEL"] = "info"
	output := runMonitorLoop(t, f, "sensor_monitor_check_complete")
	if f.sensorChecks != 1 {
		t.Fatal("startup must query the configured cluster without a slash command")
	}
	for _, event := range []string{"sensor_monitor_startup", "sensor_monitor_check_start", "sensor_monitor_acs_complete", "sensor_monitor_post_sent", "sensor_monitor_check_complete"} {
		if !strings.Contains(output.String(), `"event":"`+event+`"`) {
			t.Fatal("missing log", event, output.String())
		}
	}
	if strings.Contains(output.String(), "[ACS DEBUG]") || strings.Contains(output.String(), "rox-read") {
		t.Fatal(output.String())
	}
}

func TestSensorMonitorTimeoutCanStillDeliverUnknownNotice(t *testing.T) {
	f := sensorFixture(t, time.Now().UTC())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	f.app.S.Rox = &http.Client{Transport: monitorTransport(func(r *http.Request) (*http.Response, error) {
		probe, ok := r.Context().Deadline()
		if !ok || deadline.Sub(probe) < 30*time.Second {
			t.Error("no delivery time reserved")
		}
		return nil, context.DeadlineExceeded
	})}
	if err := f.app.checkSensorMonitor(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 1 || !strings.Contains(encode(f.posts[0]), "kan inte verifieras") {
		t.Fatal(f.posts)
	}
}

func TestOperationsSensorCommandUsesExistingSlashIntegration(t *testing.T) {
	f, _ := operationsFixture(t)
	original := f.Server.Config.Handler
	f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/clusters/cluster-123" {
			if r.Header.Get("Authorization") != "Bearer rox-read" {
				t.Error("wrong read credential")
			}
			writeJSON(w, 200, M{"cluster": M{"id": "cluster-123", "name": "labb", "healthStatus": M{"lastContact": time.Now().UTC().Format(time.RFC3339)}}})
			return
		}
		original.ServeHTTP(w, r)
	})
	form := url.Values{"token": {"slash-secret"}, "command": {"/cve"}, "text": {"sensor"}, "channel_id": {channelID}, "user_id": {ownerID}}
	req := httptest.NewRequest("POST", "/slash/cve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	f.App.ServeHTTP(response, req)
	f.App.Wait()
	if response.Code != 200 || len(f.Posts) != 1 || !strings.Contains(encode(f.Posts[0]), "nylig kontakt") {
		t.Fatal(response.Code, response.Body.String(), f.Posts)
	}
	form.Set("text", "sensor team-a")
	req = httptest.NewRequest("POST", "/slash/cve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	f.App.ServeHTTP(httptest.NewRecorder(), req)
	f.App.Wait()
	if len(f.Posts) != 1 {
		t.Fatal("sensor must not accept namespace arguments")
	}
}

func TestSensorMonitorConfigurationValidation(t *testing.T) {
	env := testEnv()
	env["SENSOR_MONITOR_ENABLED"] = "yes"
	if _, err := NewConfig(env); err == nil {
		t.Fatal("invalid boolean accepted")
	}
	delete(env, "SENSOR_MONITOR_ENABLED")
	c, err := NewConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.Flag("SENSOR_MONITOR_ENABLED", true) {
		t.Fatal("old configurations must keep working until monitoring is enabled")
	}
}
