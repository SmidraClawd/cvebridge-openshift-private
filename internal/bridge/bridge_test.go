package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var channelID = strings.Repeat("c", 26)
var ownerID = strings.Repeat("u", 26)
var botID = strings.Repeat("b", 26)
var postID = strings.Repeat("p", 26)
var imageDigest = "sha256:" + strings.Repeat("a", 64)

func testEnv() map[string]string {
	return map[string]string{
		"NAMESPACE": "cvebridge", "APP_IMAGE": "registry.acme.test/security/cvebridge:go-test", "WEBHOOK_PUBLIC_URL": "https://cvebridge.apps.acme.test",
		"MATTERMOST_INTERNAL_URL": "https://mattermost.acme.test", "STACKROX_URL": "https://central.acme.test", "STACKROX_CLUSTER_ID": "cluster-123",
		"MATTERMOST_BOT_USER_ID": botID, "MATTERMOST_BOT_TOKEN": "bot-secret", "MATTERMOST_COMMAND_TOKEN": "slash-secret",
		"STACKROX_TOKEN": "rox-read", "STACKROX_SCAN_TOKEN": "rox-scan", "STACKROX_STATUS_TOKEN": "rox-status", "STACKROX_SCHEDULE_TOKEN": "rox-scheduled",
		"MATTERMOST_CHANNEL_SCOPES": encode(map[string][]string{channelID: {"team-a"}}), "MATTERMOST_SCHEDULE_SCOPES": encode(map[string][]string{channelID: {"team-a"}}),
		"MATTERMOST_KUBE_USER_MAP": encode(map[string]string{ownerID: "alice"}), "SCHEDULE_SERVICE_USER": "system:serviceaccount:cvebridge:cvebridge-reporter",
		"MATTERMOST_DIALOG_URL": "https://cvebridge.apps.acme.test/slash/cve/dialog",
	}
}

type fixture struct {
	App         *App
	Server      *httptest.Server
	mu          sync.Mutex
	Dialog      M
	Posts       []M
	FailPost    bool
	WrongScope  bool
	Stale       bool
	Denied      bool
	ScanCalls   int
	SeenTokens  []string
	BotResponse M
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		path := r.URL.Path
		switch {
		case path == "/apis/authorization.k8s.io/v1/subjectaccessreviews":
			var p M
			_ = json.NewDecoder(r.Body).Decode(&p)
			groups := stringsOf(obj(p["spec"])["groups"])
			for _, g := range groups {
				if g == "system:masters" {
					t.Error("invented privileged group")
				}
			}
			write(M{"status": M{"allowed": !f.Denied}})
		case path == "/api/v4/users/me":
			if f.BotResponse != nil {
				write(f.BotResponse)
			} else {
				write(M{"id": botID, "is_bot": true, "roles": "system_user"})
			}
		case path == "/api/v4/users/"+ownerID:
			write(M{"id": ownerID, "email": "attacker@example.test"})
		case path == "/api/v4/channels/"+channelID:
			write(M{"id": channelID, "type": "P"})
		case strings.HasSuffix(path, "/members"):
			write([]M{{"channel_id": channelID, "user_id": ownerID}, {"channel_id": channelID, "user_id": botID}})
		case path == "/api/v4/actions/dialogs/open":
			_ = json.NewDecoder(r.Body).Decode(&f.Dialog)
			write(M{})
		case path == "/api/v4/posts/ephemeral":
			write(M{"id": postID})
		case path == "/api/v4/posts":
			if f.FailPost {
				w.WriteHeader(500)
				write(M{})
				return
			}
			var p M
			_ = json.NewDecoder(r.Body).Decode(&p)
			f.Posts = append(f.Posts, p)
			write(M{"id": postID})
		case path == "/api/v4/files":
			write(M{"file_infos": []M{{"id": strings.Repeat("f", 26)}}})
		case path == "/v1/pods":
			ns := "team-a"
			if f.WrongScope {
				ns = "other-team"
			}
			write(M{"pods": []M{{"id": "pod1", "namespace": ns, "clusterId": "cluster-123", "deploymentId": "dep1", "liveInstances": []M{{"containerName": "main", "imageDigest": imageDigest}}}}})
		case path == "/v1/deployments/dep1":
			write(M{"name": "api", "namespace": "team-a", "clusterId": "cluster-123", "containers": []M{{"name": "main", "image": M{"name": M{"fullName": "registry.acme.test/api:latest"}, "id": imageDigest}}}})
		case path == "/v1/images/scan" || strings.HasPrefix(path, "/v1/images/"):
			f.SeenTokens = append(f.SeenTokens, r.Header.Get("Authorization"))
			if path == "/v1/images/scan" {
				f.ScanCalls++
			}
			stamp := time.Now()
			if f.Stale {
				stamp = stamp.Add(-time.Hour)
			}
			write(M{"id": imageDigest, "scan": M{"scanTime": stamp.UTC().Format(time.RFC3339Nano), "components": []M{{"name": "openssl", "version": "1.0", "vulns": []M{{"cve": "CVE-2026-12345", "cvss": 9.8, "fixedBy": "2.0"}}}}}})
		case path == "/v1/integrationhealth/vulndefinitions":
			write(M{"lastUpdatedTimestamp": time.Now().UTC().Format(time.RFC3339)})
		default:
			w.WriteHeader(404)
			write(M{})
		}
	}))
	t.Cleanup(f.Server.Close)
	env := testEnv()
	env["MATTERMOST_INTERNAL_URL"] = f.Server.URL
	env["STACKROX_URL"] = f.Server.URL
	env["KUBE_API"] = f.Server.URL
	tokenfile := filepath.Join(t.TempDir(), "token")
	if e := os.WriteFile(tokenfile, []byte("kube-token"), 0600); e != nil {
		t.Fatal(e)
	}
	env["KUBE_TOKEN_FILE"] = tokenfile
	c, e := NewConfig(env)
	if e != nil {
		t.Fatal(e)
	}
	s := &Services{C: c, MM: f.Server.Client(), Rox: f.Server.Client(), Kube: f.Server.Client()}
	store, e := OpenStore(filepath.Join(t.TempDir(), "state.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.App = NewApp(context.Background(), s, store)
	return f
}
func TestEnvDataNeverExecutes(t *testing.T) {
	v, e := ReadEnv(strings.NewReader("TOKEN='$(touch /tmp/nope)`id`$HOME'\nMAP='{\"key\":\"value\"}'\n"))
	if e != nil || v["TOKEN"] != "$(touch /tmp/nope)`id`$HOME" {
		t.Fatal(v, e)
	}
	for _, s := range []string{"export A=x", "A='unterminated", "A=x\nA=y"} {
		if _, e := ReadEnv(strings.NewReader(s)); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestCommandAuthentication(t *testing.T) {
	for _, tt := range []struct {
		header, form string
		want         bool
	}{{"", "", false}, {"Token slash-secret", "", true}, {"Bearer slash-secret", "slash-secret", true}, {"Bearer wrong", "slash-secret", false}, {"Token slash-secret", "wrong", false}, {"Basic slash-secret", "", false}} {
		if got := verifyCommandToken("slash-secret", tt.header, tt.form); got != tt.want {
			t.Errorf("%+v got %v", tt, got)
		}
	}
}
func TestInvalidConfiguration(t *testing.T) {
	for _, mutate := range []func(map[string]string){func(m map[string]string) {
		m["MATTERMOST_KUBE_USER_MAP"] = encode(map[string]string{ownerID: "system:admin"})
	}, func(m map[string]string) {
		m["MATTERMOST_SCHEDULE_SCOPES"] = encode(map[string][]string{channelID: {"another-team"}})
	}, func(m map[string]string) {
		m["MATTERMOST_CHANNEL_POLICIES"] = encode(map[string]string{channelID: "everyone"})
	}} {
		m := testEnv()
		mutate(m)
		if _, e := NewConfig(m); e == nil {
			t.Error("invalid security config accepted")
		}
	}
}
func TestScheduleValidation(t *testing.T) {
	for _, times := range []string{"8:00", "08:00,08:30", "23:30,00:00", "", "00:00,05:00,10:00,15:00,20:00"} {
		if _, e := ValidateSchedule([]string{"0"}, times, "Europe/Stockholm", "scan", []string{"team-a"}); e == nil {
			t.Errorf("accepted %q", times)
		}
	}
	if _, e := ValidateSchedule([]string{"7"}, "08:00", "Europe/Stockholm", "scan", []string{"team-a"}); e == nil {
		t.Fatal("bad day accepted")
	}
}
func TestDSTFirstFoldAndMissingTime(t *testing.T) {
	c, e := ValidateSchedule([]string{"6"}, "02:30", "Europe/Stockholm", "scan", []string{"team-a"})
	if e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct{ after, want string }{{"2026-03-28T23:00:00Z", "2026-04-05T00:30:00Z"}, {"2026-10-24T22:00:00Z", "2026-10-25T00:30:00Z"}, {"2026-10-25T00:45:00Z", "2026-11-01T01:30:00Z"}} {
		after, _ := time.Parse(time.RFC3339, tt.after)
		next, e := NextDue(c, after)
		if e != nil || next.UTC().Format(time.RFC3339) != tt.want {
			t.Errorf("%s -> %s (%v), want %s", tt.after, next, e, tt.want)
		}
	}
}
func TestScanScopeAndFreshness(t *testing.T) {
	for _, mode := range []string{"normal", "wrongscope", "stale"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.WrongScope = mode == "wrongscope"
			f.Stale = mode == "stale"
			r, e := f.App.S.Scan(context.Background(), []string{"team-a"}, func() error { return nil }, true, false)
			if mode == "wrongscope" {
				if e == nil || f.ScanCalls != 0 {
					t.Fatal("out-of-scope inventory was scanned")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode == "stale" {
				if num(r["failedImages"]) != 1 || len(arr(r["rows"])) != 0 {
					t.Fatal("stale scan accepted")
				}
			} else if num(r["scannedImages"]) != 1 || len(arr(r["rows"])) != 1 {
				t.Fatal(r)
			}
		})
	}
}
func TestScheduledCredentialSeparation(t *testing.T) {
	f := newFixture(t)
	_, e := f.App.S.Scan(context.Background(), []string{"team-a"}, func() error { return nil }, true, true)
	if e != nil {
		t.Fatal(e)
	}
	if !same(f.SeenTokens, []string{"Bearer rox-scheduled"}) {
		t.Fatal(f.SeenTokens)
	}
}
func submission(key string) M {
	return M{"type": "dialog_submission", "callback_id": callbackID, "state": key, "user_id": ownerID, "channel_id": channelID, "submission": M{"action": "save", "days": "0,1,2,3,4", "times": "08:00, 15:00", "timezone": "Europe/Stockholm", "mode": "scan", "enabled": "yes", "namespaces": "team-a"}}
}
func open(t *testing.T, f *fixture) string {
	t.Helper()
	if e := f.App.OpenDialog(context.Background(), ownerID, channelID, "trigger"); e != nil {
		t.Fatal(e)
	}
	return str(obj(f.Dialog["dialog"])["state"])
}
func TestNativeDialogOwnerReplayAndRevision(t *testing.T) {
	f := newFixture(t)
	key := open(t, f)
	p := submission(key)
	p["user_id"] = botID
	if e := f.App.SubmitDialog(context.Background(), key, p); e == nil {
		t.Fatal("wrong owner accepted")
	}
	p["user_id"] = ownerID
	if e := f.App.SubmitDialog(context.Background(), key, p); e != nil {
		t.Fatal(e)
	}
	if e := f.App.SubmitDialog(context.Background(), key, p); e == nil {
		t.Fatal("replay accepted")
	}
	current, e := f.App.Store.Schedule(channelID)
	if e != nil || current.Revision != 1 || !current.Enabled {
		t.Fatal(current, e)
	}
	old := open(t, f)
	fresh := open(t, f)
	if e = f.App.SubmitDialog(context.Background(), fresh, submission(fresh)); e != nil {
		t.Fatal(e)
	}
	if e = f.App.SubmitDialog(context.Background(), old, submission(old)); e == nil {
		t.Fatal("stale revision accepted")
	}
}
func TestNativeDialogRechecksScope(t *testing.T) {
	f := newFixture(t)
	key := open(t, f)
	p := submission(key)
	obj(p["submission"])["namespaces"] = "secret-team"
	if e := f.App.SubmitDialog(context.Background(), key, p); e == nil {
		t.Fatal("foreign namespace accepted")
	}
	f.Denied = true
	obj(p["submission"])["namespaces"] = "team-a"
	if e := f.App.SubmitDialog(context.Background(), key, p); e == nil {
		t.Fatal("revoked permission accepted")
	}
}
func TestAlertStateAdvancesOnlyAfterAck(t *testing.T) {
	f := newFixture(t)
	r := func(cve string) M {
		return M{"kind": "scan", "namespaces": []string{"team-a"}, "rows": []any{M{"namespace": "team-a", "cve": cve, "cvss": 9.8}}, "database": M{"state": "recent"}}
	}
	ctx := context.Background()
	f.FailPost = true
	if _, e := f.App.Store.Publish(ctx, f.App.S, channelID, r("CVE-2026-12345")); e == nil {
		t.Fatal("failure accepted")
	}
	var n int
	_ = f.App.Store.DB.QueryRow(`SELECT COUNT(*) FROM cve_seen`).Scan(&n)
	if n != 0 {
		t.Fatal("failed delivery consumed alert")
	}
	f.FailPost = false
	baseline := r("CVE-2026-12345")
	if _, e := f.App.Store.Publish(ctx, f.App.S, channelID, baseline); e != nil {
		t.Fatal(e)
	}
	if len(stringsOf(baseline["alertCves"])) != 0 || !boolean(baseline["alertBaseline"]) {
		t.Fatal("baseline pinged")
	}
	next := r("CVE-2026-99999")
	if _, e := f.App.Store.Publish(ctx, f.App.S, channelID, next); e != nil {
		t.Fatal(e)
	}
	if len(stringsOf(next["alertCves"])) != 1 {
		t.Fatal("new critical CVE missing")
	}
	again := r("CVE-2026-99999")
	if _, e := f.App.Store.Publish(ctx, f.App.S, channelID, again); e != nil {
		t.Fatal(e)
	}
	if len(stringsOf(again["alertCves"])) != 0 {
		t.Fatal("duplicate alert")
	}
}
func TestManualCommandEntirelyInMattermost(t *testing.T) {
	f := newFixture(t)
	form := url.Values{"token": {"slash-secret"}, "command": {"/cve"}, "text": {"scan team-a"}, "channel_id": {channelID}, "user_id": {ownerID}}
	req := httptest.NewRequest("POST", "/slash/cve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.App.ServeHTTP(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), "/requests/") {
		t.Fatal(w.Code, w.Body.String())
	}
	f.App.tasks.Wait()
	if len(f.Posts) != 1 {
		t.Fatal("no native report", f.Posts)
	}
	if f.ScanCalls != 1 {
		t.Fatal("scan not executed")
	}
}
func TestPublicListenerRejectsForgedIdentityAndOversizedInput(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/", "/search", "/jobs/fake", "/requests/fake"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("X-Forwarded-Email", "admin")
		w := httptest.NewRecorder()
		f.App.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/slash/cve", strings.NewReader("token=wrong&command=/cve&text=scan"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.App.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "/slash/cve", strings.NewReader(strings.Repeat("x", 17000)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	f.App.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
func TestRenderDeploymentAndSeparateBootstrap(t *testing.T) {
	env := testEnv()
	for _, part := range []string{"deployment", "bootstrap"} {
		var out bytes.Buffer
		if e := Render(&out, env, part); e != nil {
			t.Fatal(e)
		}
		var list M
		if e := json.Unmarshal(out.Bytes(), &list); e != nil {
			t.Fatal(e)
		}
		if str(list["kind"]) != "List" {
			t.Fatal(list)
		}
		kinds := map[string]bool{}
		for _, v := range arr(list["items"]) {
			r := obj(v)
			kind := str(r["kind"])
			kinds[kind] = true
			if part == "deployment" && (kind == "ClusterRole" || kind == "ClusterRoleBinding" || kind == "Namespace") {
				t.Fatal("cluster-scoped object in regular deployment")
			}
			if kind == "Deployment" {
				pod := obj(obj(obj(r["spec"])["template"])["spec"])
				if len(arr(pod["containers"])) != 1 {
					t.Fatal("unexpected website/proxy")
				}
				if num(obj(r["spec"])["replicas"]) != 1 {
					t.Fatal("unsafe replicas")
				}
			}
			if kind != "Secret" && strings.Contains(encode(r), "bot-secret") {
				t.Fatal("token outside Secret")
			}
		}
		if part == "deployment" && (!kinds["Deployment"] || !kinds["Route"] || !kinds["PersistentVolumeClaim"]) {
			t.Fatal(kinds)
		}
		if part == "bootstrap" && !kinds["ClusterRole"] {
			t.Fatal(kinds)
		}
	}
}
func TestRenderRejectsUnfilledOrUnsafeInputs(t *testing.T) {
	for k, v := range map[string]string{"APP_IMAGE": "$(id)", "MATTERMOST_BOT_TOKEN": "CHANGE_ME", "WEBHOOK_PUBLIC_URL": "http://bad.test", "SCHEDULE_SERVICE_USER": "system:serviceaccount:other:reporter"} {
		env := testEnv()
		env[k] = v
		if e := Render(&bytes.Buffer{}, env, "deployment"); e == nil {
			t.Errorf("accepted %s", k)
		}
	}
}
func TestReportBoundsAndMentions(t *testing.T) {
	r := M{"kind": "scan", "rows": []any{M{"cve": "CVE-2026-12345", "component": "@channel <script>", "cvss": 9.8}}, "database": M{"state": "unknown"}}
	text := encode(ResultMessage(r))
	if strings.Contains(text, "@channel") {
		t.Fatal("untrusted mention")
	}
	if !strings.Contains(text, "Åtgärd") {
		t.Fatal("missing action")
	}
	r["alertCves"] = []string{"CVE-2026-12345"}
	if !strings.Contains(encode(ResultMessage(r)), "@channel") {
		t.Fatal("missing authorized alert")
	}
}
func TestDurableScheduleRestartAndMissedSlots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	s, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	c, e := ValidateSchedule([]string{"0", "1", "2", "3", "4", "5", "6"}, "08:00", "Europe/Stockholm", "scan", []string{"team-a"})
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.Save(channelID, ownerID, c, true, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Enqueue(channelID, v.Revision); e != nil {
		t.Fatal(e)
	}
	r, e := s.TakeRun()
	if e != nil || r == nil {
		t.Fatal(r, e)
	}
	_ = s.Close()
	s, e = OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var state string
	if e = s.DB.QueryRow(`SELECT state FROM schedule_runs WHERE id=?`, r.ID).Scan(&state); e != nil || state != "interrupted" {
		t.Fatal(state, e)
	}
	if _, e = s.Save(channelID, ownerID, c, true, 0); e == nil {
		t.Fatal("stale save allowed")
	}
	past := timestamp() - 1000
	_, _ = s.DB.Exec(`UPDATE schedules SET next_due=?`, past)
	if e = s.ClaimDue(timestamp()); e != nil {
		t.Fatal(e)
	}
	var missed int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM schedule_runs WHERE state='missed'`).Scan(&missed)
	if missed != 1 {
		t.Fatal(fmt.Sprint("backlog replayed: ", missed))
	}
}

func TestWorkerDeliversScheduledRunAndRejectsPausedRevision(t *testing.T) {
	f := newFixture(t)
	c, e := ValidateSchedule([]string{"0", "1", "2", "3", "4", "5", "6"}, "08:00", "Europe/Stockholm", "scan", []string{"team-a"})
	if e != nil {
		t.Fatal(e)
	}
	c.Policy = "common"
	v, e := f.App.Store.Save(channelID, ownerID, c, true, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.App.Store.Enqueue(channelID, v.Revision); e != nil {
		t.Fatal(e)
	}
	run, e := f.App.Store.TakeRun()
	if e != nil {
		t.Fatal(e)
	}
	f.App.execute(channelID, "", "scan", c.Namespaces, run)
	var state string
	if e = f.App.Store.DB.QueryRow(`SELECT state FROM schedule_runs WHERE id=?`, run.ID).Scan(&state); e != nil || state != "done" {
		t.Fatal(state, e)
	}
	if len(f.Posts) != 1 || f.ScanCalls != 1 {
		t.Fatal("scheduled report missing")
	}
	if _, e = f.App.Store.Save(channelID, ownerID, c, false, v.Revision); e != nil {
		t.Fatal(e)
	}
	f.App.execute(channelID, "", "scan", c.Namespaces, run)
	if f.ScanCalls != 1 || len(f.Posts) != 1 {
		t.Fatal("paused schedule still scanned or published")
	}
}

func TestManualDeniedIdentityNeverScans(t *testing.T) {
	f := newFixture(t)
	f.Denied = true
	f.App.execute(channelID, ownerID, "scan", []string{"team-a"}, nil)
	if f.ScanCalls != 0 || len(f.Posts) != 0 {
		t.Fatal("unauthorized findings published")
	}
}

func TestCABundleCannotCopyPrivateKeysToConfigMap(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(path, cert, 0600); e != nil {
		t.Fatal(e)
	}
	env := testEnv()
	env["STACKROX_CA_FILE"] = path
	if e := Render(&bytes.Buffer{}, env, "deployment"); e != nil {
		t.Fatal(e)
	}
	cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private-data")})...)
	if e := os.WriteFile(path, cert, 0600); e != nil {
		t.Fatal(e)
	}
	if e := Render(&bytes.Buffer{}, env, "deployment"); e == nil {
		t.Fatal("private key copied into public certificate ConfigMap")
	}
}

func TestInvalidCVSSDoesNotCreateCriticalAlert(t *testing.T) {
	f := newFixture(t)
	f.App.S.C.Env["CVE_ALERT_FIRST_REPORT"] = "true"
	r := M{"kind": "scan", "namespaces": []string{"team-a"}, "rows": []any{M{"namespace": "team-a", "cve": "CVE-2026-12345", "cvss": 20.0}}, "database": M{"state": "recent"}}
	if _, e := f.App.Store.Publish(context.Background(), f.App.S, channelID, r); e != nil {
		t.Fatal(e)
	}
	if len(stringsOf(r["alertCves"])) != 0 {
		t.Fatal("invalid CVSS value generated a critical alert")
	}
}

func shortEnv() map[string]string {
	m := testEnv()
	for _, k := range []string{"APP_IMAGE", "MATTERMOST_BOT_USER_ID", "STACKROX_URL", "MATTERMOST_CHANNEL_SCOPES", "MATTERMOST_SCHEDULE_SCOPES", "SCHEDULE_SERVICE_USER"} {
		delete(m, k)
	}
	m["NAMESPACE"] = "security-bot"
	m["MATTERMOST_CHANNEL_ID"] = channelID
	m["SCAN_NAMESPACES"] = "team-a, team-b,team-a"
	return m
}

func TestShortEnvProducesInternalRegistryDeployment(t *testing.T) {
	m := shortEnv()
	m["IMAGE_TAG"] = "go-abcd123"
	var out bytes.Buffer
	if e := Render(&out, m, "deployment"); e != nil {
		t.Fatal(e)
	}
	var list M
	if e := json.Unmarshal(out.Bytes(), &list); e != nil {
		t.Fatal(e)
	}
	var config M
	found := false
	for _, v := range arr(list["items"]) {
		r := obj(v)
		switch str(r["kind"]) {
		case "Deployment":
			pod := obj(obj(obj(r["spec"])["template"])["spec"])
			container := obj(arr(pod["containers"])[0])
			if str(container["image"]) != OpenShiftRegistry+"/security-bot/cvebridge:go-abcd123" {
				t.Fatal(container["image"])
			}
			if len(arr(pod["imagePullSecrets"])) != 0 {
				t.Fatal("unexpected external registry credentials")
			}
			found = true
		case "ConfigMap":
			if str(obj(r["metadata"])["name"]) == "cvebridge-config" {
				config = obj(r["data"])
			}
		}
	}
	if !found {
		t.Fatal("missing deployment")
	}
	values := map[string]string{}
	for k, v := range config {
		values[k] = str(v)
	}
	c, e := NewConfig(values)
	if e != nil {
		t.Fatal(e)
	}
	if !same(c.Scopes[channelID], []string{"team-a", "team-b"}) || !same(c.ScheduleScopes[channelID], c.Scopes[channelID]) {
		t.Fatal(c.Scopes, c.ScheduleScopes)
	}
	if c.Get("SCHEDULE_SERVICE_USER", "") != "system:serviceaccount:security-bot:cvebridge-reporter" {
		t.Fatal("namespace was not propagated")
	}
	if _, ok := m["MATTERMOST_CHANNEL_SCOPES"]; ok {
		t.Fatal("caller configuration mutated")
	}
}

func TestShortEnvStillRequiresApprovedIdentitiesAndSeparateTokens(t *testing.T) {
	for _, key := range []string{"MATTERMOST_KUBE_USER_MAP", "STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"} {
		m := shortEnv()
		delete(m, key)
		if e := Render(&bytes.Buffer{}, m, "deployment"); e == nil {
			t.Errorf("missing %s was silently inferred", key)
		}
	}
	for _, ns := range []string{"*", "team-a,../secret", ""} {
		m := shortEnv()
		m["SCAN_NAMESPACES"] = ns
		if _, e := NewConfig(m); e == nil {
			t.Errorf("invalid namespace set accepted: %s", ns)
		}
	}
}

func TestAdvancedScopesRemainExplicit(t *testing.T) {
	m := shortEnv()
	m["MATTERMOST_CHANNEL_SCOPES"] = encode(map[string][]string{channelID: {"team-a"}})
	m["MATTERMOST_SCHEDULE_SCOPES"] = "{}"
	c, e := NewConfig(m)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.ScheduleScopes) != 0 || !same(c.Scopes[channelID], []string{"team-a"}) {
		t.Fatal("explicit policy was overwritten")
	}
	m["APP_IMAGE"] = OpenShiftRegistry + "/other-project/cvebridge:v1"
	if e := Render(&bytes.Buffer{}, m, "deployment"); e == nil {
		t.Fatal("internal image from another namespace accepted")
	}
}

func TestAutomaticBotIdentityRejectsHumanAdminAndMismatch(t *testing.T) {
	f := newFixture(t)
	delete(f.App.S.C.Env, "MATTERMOST_BOT_USER_ID")
	if id, e := f.App.S.Bot(context.Background()); e != nil || id != botID {
		t.Fatal(id, e)
	}
	if _, e := f.App.S.ScheduledAudience(context.Background(), channelID, []string{"team-a"}); e != nil {
		t.Fatal(e)
	}
	for _, response := range []M{{"id": botID, "is_bot": false, "roles": "system_user"}, {"id": botID, "is_bot": true, "roles": "system_admin"}, {"id": "bad", "is_bot": true, "roles": "system_user"}} {
		f.BotResponse = response
		if _, e := f.App.S.Bot(context.Background()); e == nil {
			t.Fatal("invalid bot identity accepted")
		}
	}
	f.BotResponse = nil
	f.App.S.C.Env["MATTERMOST_BOT_USER_ID"] = ownerID
	if _, e := f.App.S.Bot(context.Background()); e == nil {
		t.Fatal("configured bot ID mismatch accepted")
	}
}
