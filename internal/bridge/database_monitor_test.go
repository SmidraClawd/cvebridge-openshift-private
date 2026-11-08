package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var opsID = strings.Repeat("o", 26)

type monitorTransport func(*http.Request) (*http.Response, error)

func (f monitorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type monitorFixture struct {
	mu           sync.Mutex
	stamp        string
	statusCode   int
	postCode     int
	badAck       bool
	public       bool
	deleted      bool
	wrongMember  bool
	adminBot     bool
	checks       int
	sensorChecks int
	sensorCode   int
	sensorReply  M
	posts        []M
	server       *httptest.Server
	app          *App
}

func newMonitorFixture(t *testing.T) *monitorFixture {
	t.Helper()
	f := &monitorFixture{statusCode: 200, postCode: 201}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		write := func(m any) { _ = json.NewEncoder(w).Encode(m) }
		switch r.URL.Path {
		case "/v1/clusters/cluster-123":
			f.sensorChecks++
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer rox-read" || r.URL.RawQuery != "" {
				t.Error("sensor monitoring must read only the configured cluster with the read credential")
			}
			code := f.sensorCode
			if code == 0 {
				code = 200
			}
			w.WriteHeader(code)
			write(f.sensorReply)
		case "/v1/integrationhealth/vulndefinitions":
			f.checks++
			if r.Method != "GET" || r.URL.Query().Get("component") != "SCANNER_V4" || r.Header.Get("Authorization") != "Bearer rox-status" {
				t.Error("monitor must read Scanner V4 metadata with the status credential")
			}
			w.WriteHeader(f.statusCode)
			write(M{"lastUpdatedTimestamp": f.stamp})
		case "/api/v4/users/me":
			roles := "system_user"
			if f.adminBot {
				roles += " system_admin"
			}
			write(M{"id": botID, "is_bot": true, "roles": roles})
		case "/api/v4/channels/" + opsID:
			kind := "P"
			if f.public {
				kind = "O"
			}
			deleted := 0
			if f.deleted {
				deleted = 123
			}
			write(M{"id": opsID, "type": kind, "delete_at": deleted})
		case "/api/v4/channels/" + opsID + "/members/" + botID:
			member := botID
			if f.wrongMember {
				member = ownerID
			}
			write(M{"channel_id": opsID, "user_id": member})
		case "/api/v4/posts":
			var post M
			if e := json.NewDecoder(r.Body).Decode(&post); e != nil {
				t.Error(e)
			}
			if str(post["channel_id"]) != opsID || strings.Contains(encode(post), "@channel") || post["file_ids"] != nil {
				t.Error("monitor must send a simple ops notice without CVE pings or report files")
			}
			f.posts = append(f.posts, post)
			w.WriteHeader(f.postCode)
			id := postID
			if f.badAck {
				id = ""
			}
			write(M{"id": id})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			write(M{})
		}
	}))
	t.Cleanup(f.server.Close)
	env := testEnv()
	env["MATTERMOST_INTERNAL_URL"], env["STACKROX_URL"] = f.server.URL, f.server.URL
	env["DATABASE_MONITOR_CHANNEL_ID"] = opsID
	c, e := NewConfig(env)
	if e != nil {
		t.Fatal(e)
	}
	store, e := OpenStore(filepath.Join(t.TempDir(), "state.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.app.Store.Close() })
	f.app = NewApp(context.Background(), &Services{C: c, MM: f.server.Client(), Rox: f.server.Client()}, store)
	return f
}

func TestDatabaseStatusFreshness(t *testing.T) {
	f := newMonitorFixture(t)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name, stamp, want string
		code              int
	}{
		{"fresh", now.Add(-time.Hour).Format(time.RFC3339), "recent", 200},
		{"at limit", now.Add(-24 * time.Hour).Format(time.RFC3339), "recent", 200},
		{"stale", now.Add(-25 * time.Hour).Format(time.RFC3339), "stale", 200},
		{"missing", "", "unknown", 200},
		{"invalid", "not-a-time", "unknown", 200},
		{"future", now.Add(time.Hour).Format(time.RFC3339), "unknown", 200},
		{"forbidden", now.Format(time.RFC3339), "unknown", 403},
		{"unavailable", now.Format(time.RFC3339), "unknown", 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f.stamp, f.statusCode = tt.stamp, tt.code
			r := f.app.S.databaseStatusAt(context.Background(), now)
			if str(r["state"]) != tt.want || str(r["checkedAt"]) != now.Format(time.RFC3339) {
				t.Fatal(r)
			}
			if tt.want == "unknown" && (str(r["reason"]) == "" || r["ageHours"] != nil) {
				t.Fatal("unknown status must explain why and never invent an age", r)
			}
		})
	}
}

func TestDatabaseMonitorTransitionsAndRestart(t *testing.T) {
	f := newMonitorFixture(t)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	f.stamp = now.Add(-time.Hour).Format(time.RFC3339)
	check := func(when time.Time, want int) {
		t.Helper()
		if e := f.app.checkDatabaseMonitor(context.Background(), when); e != nil {
			t.Fatal(e)
		}
		if len(f.posts) != want {
			t.Fatalf("at %s: got %d posts, want %d", when, len(f.posts), want)
		}
	}
	check(now, 1)
	check(now.Add(time.Hour), 1)
	// Reopen the same SQLite file, as a replacement pod does on the PVC.
	var path string
	var seq int
	var name string
	if e := f.app.Store.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	if e := f.app.Store.Close(); e != nil {
		t.Fatal(e)
	}
	store, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	f.app = NewApp(context.Background(), f.app.S, store)
	check(now.Add(time.Hour), 1)
	f.stamp = now.Add(-25 * time.Hour).Format(time.RFC3339)
	check(now.Add(2*time.Hour), 2)
	check(now.Add(3*time.Hour), 2)
	check(now.Add(26*time.Hour), 3) // Daily reminder while still stale.
	f.stamp = now.Add(27 * time.Hour).Format(time.RFC3339)
	check(now.Add(27*time.Hour), 4)
	if !strings.Contains(encode(f.posts[3]), "inom gränsen igen") {
		t.Fatal("recovery must be visible")
	}
	check(now.Add(28*time.Hour), 4)
	f.stamp = now.Add(50 * time.Hour).Format(time.RFC3339)
	check(now.Add(51*time.Hour), 5) // Healthy daily heartbeat.
	f.statusCode = 503
	check(now.Add(52*time.Hour), 6)
	check(now.Add(53*time.Hour), 6)
	if !strings.Contains(encode(f.posts[5]), "kan inte verifieras") {
		t.Fatal("ACS failure must produce an unknown-status warning")
	}
	for _, p := range f.posts {
		s := encode(p)
		if strings.Contains(s, "team-a") || strings.Contains(s, "rox-status") || strings.Contains(s, f.server.URL) {
			t.Fatal("ops notices must not include workload data, credentials or internal addresses")
		}
	}
}

func TestDatabaseMonitorRetriesUnconfirmedDelivery(t *testing.T) {
	for _, badAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP error", true: "missing post ID"}[badAck], func(t *testing.T) {
			f := newMonitorFixture(t)
			now := time.Now().UTC()
			f.stamp = now.Add(-30 * time.Hour).Format(time.RFC3339)
			f.badAck = badAck
			if !badAck {
				f.postCode = 500
			}
			if e := f.app.checkDatabaseMonitor(context.Background(), now); e == nil {
				t.Fatal("unconfirmed post was accepted")
			}
			var count int
			if e := f.app.Store.DB.QueryRow("SELECT count(*) FROM database_monitor").Scan(&count); e != nil || count != 0 {
				t.Fatal("failed delivery advanced state", count, e)
			}
			f.postCode, f.badAck = 201, false
			if e := f.app.checkDatabaseMonitor(context.Background(), now.Add(databaseRetryInterval)); e != nil {
				t.Fatal(e)
			}
			if len(f.posts) != 2 {
				t.Fatal("delivery was not retried")
			}
		})
	}
}

func TestDatabaseMonitorRestrictsDestination(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*monitorFixture)
	}{
		{"public channel", func(f *monitorFixture) { f.public = true }},
		{"archived channel", func(f *monitorFixture) { f.deleted = true }},
		{"wrong membership", func(f *monitorFixture) { f.wrongMember = true }},
		{"admin bot", func(f *monitorFixture) { f.adminBot = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newMonitorFixture(t)
			f.stamp = time.Now().UTC().Format(time.RFC3339)
			tt.mutate(f)
			if e := f.app.checkDatabaseMonitor(context.Background(), time.Now()); e == nil || len(f.posts) != 0 {
				t.Fatal("monitor posted to an unverified destination", e)
			}
		})
	}
}

func TestDatabaseMonitorConfig(t *testing.T) {
	for _, value := range []string{"wrong", "CHANGE_ME_CHANNEL_ID", "@channel"} {
		env := testEnv()
		env["DATABASE_MONITOR_CHANNEL_ID"] = value
		if _, e := NewConfig(env); e == nil {
			t.Fatal("invalid monitor channel accepted", value)
		}
	}
	env := testEnv()
	env["DATABASE_MONITOR_CHANNEL_ID"], env["STACKROX_SCANNER_COMPONENT"] = opsID, "typo"
	if _, e := NewConfig(env); e == nil {
		t.Fatal("invalid monitor component accepted")
	}
	env["STACKROX_SCANNER_COMPONENT"] = "SCANNER_V4"
	if _, e := NewConfig(env); e != nil {
		t.Fatal(e)
	}
}

func TestDatabaseMonitorCadenceIndependentOfScanWorker(t *testing.T) {
	f := newMonitorFixture(t)
	now := time.Now().UTC()
	f.stamp = now.Format(time.RFC3339)
	f.app.worker.Lock() // Simulate a long-running image scan.
	defer f.app.worker.Unlock()
	f.app.startDatabaseMonitor(now)
	f.app.Wait()
	f.app.startDatabaseMonitor(now.Add(59 * time.Minute))
	f.app.Wait()
	if f.checks != 1 || len(f.posts) != 1 {
		t.Fatal("monitor was blocked by scan or checked too frequently", f.checks, len(f.posts))
	}
	f.app.startDatabaseMonitor(now.Add(time.Hour))
	f.app.Wait()
	if f.checks != 2 || len(f.posts) != 1 {
		t.Fatal("hourly check or notification suppression failed", f.checks, len(f.posts))
	}
	f.app.S.C.Env["DATABASE_MONITOR_CHANNEL_ID"] = ""
	f.app.startDatabaseMonitor(now.Add(2 * time.Hour))
	f.app.Wait()
	if f.checks != 2 {
		t.Fatal("disabled monitor contacted ACS")
	}
}

func TestDatabaseMonitorRetriesAndCancellation(t *testing.T) {
	f := newMonitorFixture(t)
	now := time.Now().UTC()
	f.stamp, f.postCode = now.Format(time.RFC3339), 503
	f.app.startDatabaseMonitor(now)
	f.app.Wait()
	if f.app.monitorNext.After(now.Add(databaseRetryInterval + time.Minute)) {
		t.Fatal("failed delivery should retry in 5 minutes")
	}
	f.postCode = 201
	f.app.startDatabaseMonitor(now.Add(6 * time.Minute))
	f.app.Wait()
	if len(f.posts) != 2 {
		t.Fatal("delivery retry missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.app.ctx = ctx
	cancel()
	f.app.startDatabaseMonitor(now.Add(2 * time.Hour))
	f.app.Wait()
	if f.checks != 2 {
		t.Fatal("cancelled app started another monitor request")
	}
}

func TestDatabaseMonitorTimeoutStillDeliversWarning(t *testing.T) {
	f := newMonitorFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	f.app.S.Rox = &http.Client{Transport: monitorTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || parentDeadline.Sub(deadline) < 30*time.Second {
			t.Error("ACS probe must leave enough time for the ops notice")
		}
		return nil, context.DeadlineExceeded
	})}
	if e := f.app.checkDatabaseMonitor(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if len(f.posts) != 1 || !strings.Contains(encode(f.posts[0]), "kan inte verifieras") {
		t.Fatal("ACS timeout prevented the unknown-status notice")
	}
}
