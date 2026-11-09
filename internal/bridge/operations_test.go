package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func operationsFixture(t *testing.T) (*fixture, *sync.Map) {
	t.Helper()
	f := newFixture(t)
	env := f.App.S.C.Env
	delete(env, "ACCESS_MODE") // Operations is the private project's default.
	delete(env, "MATTERMOST_KUBE_USER_MAP")
	env["MATTERMOST_CHANNEL_ID"] = channelID
	env["KUBE_CA_FILE"] = "/does-not-exist/ca.crt"
	config, err := NewConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(config)
	if err != nil {
		t.Fatal("operations must start without Kubernetes credentials", err)
	}
	if services.Kube != nil || len(config.Users) != 0 {
		t.Fatal("operations unexpectedly depends on Kubernetes or user mappings")
	}
	f.App.S = services
	members := &sync.Map{}
	members.Store(ownerID, true)
	members.Store(botID, true)
	original := f.Server.Config.Handler
	f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "subjectaccessreviews") || strings.HasPrefix(r.URL.Path, "/api/v4/users/") && r.URL.Path != "/api/v4/users/me" || r.URL.Path == "/api/v4/channels/"+channelID+"/members" {
			t.Error("operations performed a per-user or Kubernetes check", r.URL.Path)
			http.Error(w, "unexpected identity check", http.StatusForbidden)
			return
		}
		if prefix := "/api/v4/channels/" + channelID + "/members/"; strings.HasPrefix(r.URL.Path, prefix) {
			id := strings.TrimPrefix(r.URL.Path, prefix)
			if _, present := members.Load(id); present {
				writeJSON(w, 200, M{"channel_id": channelID, "user_id": id})
			} else {
				writeJSON(w, 404, M{})
			}
			return
		}
		original.ServeHTTP(w, r)
	})
	return f, members
}

func TestOperationsMembersRunStatusScanAndReportWithoutUserMapping(t *testing.T) {
	f, members := operationsFixture(t)
	colleague := strings.Repeat("n", 26)
	members.Store(colleague, true) // Inviting a colleague needs no config change.
	for i, command := range []string{"status", "scan team-a", "report team-a"} {
		form := url.Values{"token": {"slash-secret"}, "command": {"/cve"}, "text": {command}, "channel_id": {channelID}, "user_id": {colleague}}
		request := httptest.NewRequest("POST", "/slash/cve", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		f.App.ServeHTTP(response, request)
		f.App.Wait()
		if response.Code != http.StatusOK || len(f.Posts) != i+1 {
			t.Fatal(command, response.Code, response.Body.String(), f.Posts)
		}
	}
	if f.ScanCalls != 1 {
		t.Fatal("status or report unexpectedly triggered a fresh scan", f.ScanCalls)
	}
	if f.FileUploads != 0 {
		t.Fatal("scan/report must not upload a JSON attachment")
	}
}

func TestOperationsScheduleWorksWithoutReporterOrPersonalAccount(t *testing.T) {
	f, members := operationsFixture(t)
	key := open(t, f)
	if err := f.App.SubmitDialog(context.Background(), key, submission(key)); err != nil {
		t.Fatal(err)
	}
	// A saved schedule is owned by the channel and survives the creator leaving.
	members.Delete(ownerID)
	current, err := f.App.Store.Schedule(channelID)
	if err != nil {
		t.Fatal(err)
	}
	// Existing schedules from the earlier sharing policy also keep working.
	current.Config.Policy = "common"
	current, err = f.App.Store.Save(channelID, ownerID, current.Config, true, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.App.Store.Enqueue(channelID, current.Revision); err != nil {
		t.Fatal(err)
	}
	run, err := f.App.Store.TakeRun()
	if err != nil || run == nil {
		t.Fatal(run, err)
	}
	f.App.execute(channelID, "", "scan", current.Config.Namespaces, run)
	var state string
	if err := f.App.Store.DB.QueryRow(`SELECT state FROM schedule_runs WHERE id=?`, run.ID).Scan(&state); err != nil || state != "done" {
		t.Fatal(state, err)
	}
	if f.ScanCalls != 1 {
		t.Fatal("scheduled scan was not performed")
	}
}

func TestOperationsStillRestrictsChannelNamespacesAndMembership(t *testing.T) {
	f, members := operationsFixture(t)
	for _, request := range []struct{ owner, channel, namespace string }{
		{ownerID, strings.Repeat("x", 26), "team-a"},
		{ownerID, channelID, "secret-team"},
		{strings.Repeat("z", 26), channelID, "team-a"},
	} {
		if _, err := f.App.S.ActorAudience(context.Background(), request.owner, request.channel, []string{request.namespace}); err == nil {
			t.Fatal("unconfigured channel, namespace or nonmember accepted", request)
		}
	}
	members.Delete(botID)
	if _, err := f.App.S.ScheduledAudience(context.Background(), channelID, nil); err == nil {
		t.Fatal("scheduled report accepted after bot left channel")
	}
}

func TestOperationsConfigurationIgnoresLegacyMappingsAndRequiresOneChannel(t *testing.T) {
	env := shortEnv()
	env["ACCESS_MODE"] = "operations"
	env["MATTERMOST_KUBE_USER_MAP"] = "obsolete-not-json"
	env["SCHEDULE_SERVICE_USER"] = "obsolete-reporter"
	if _, err := NewConfig(env); err != nil {
		t.Fatal("legacy identity settings must not affect operations", err)
	}
	delete(env, "MATTERMOST_CHANNEL_ID")
	if _, err := NewConfig(env); err == nil {
		t.Fatal("operations requires an explicit drift channel")
	}
	env["ACCESS_MODE"] = "unknown"
	if _, err := NewConfig(env); err == nil {
		t.Fatal("unknown access mode accepted")
	}
}

func TestOperationsRejectsPublicOrArchivedChannel(t *testing.T) {
	for _, channel := range []M{
		{"id": channelID, "type": "O"},
		{"id": channelID, "type": "P", "delete_at": 1},
	} {
		f, _ := operationsFixture(t)
		original := f.Server.Config.Handler
		f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v4/channels/"+channelID {
				writeJSON(w, http.StatusOK, channel)
				return
			}
			original.ServeHTTP(w, r)
		})
		if _, err := f.App.S.ActorAudience(context.Background(), ownerID, channelID, nil); err == nil {
			t.Fatal("public or archived channel accepted", channel)
		}
	}
}
