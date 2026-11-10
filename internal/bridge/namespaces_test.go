package bridge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestClusterWildcardConfiguration(t *testing.T) {
	for _, test := range []struct {
		mode, scope string
		valid       bool
	}{
		{"operations", "*", true}, {"operations", " * ", true},
		{"operations", "team-a,team-b", true},
		{"operations", "*,team-a", false}, {"operations", "team-*", false},
		{"operations", "*,*", false}, {"per-user", "*", false},
	} {
		t.Run(test.mode+"/"+test.scope, func(t *testing.T) {
			env := shortEnv()
			env["ACCESS_MODE"], env["SCAN_NAMESPACES"] = test.mode, test.scope
			config, err := NewConfig(env)
			if (err == nil) != test.valid {
				t.Fatal("unexpected wildcard validation", err)
			}
			if err == nil && strings.TrimSpace(test.scope) == "*" && (!allNamespaceScope(config.Scopes[channelID]) || !allNamespaceScope(config.ScheduleScopes[channelID])) {
				t.Fatal("wildcard was not preserved for commands and schedules", config)
			}
		})
	}
	// Advanced scopes keep priority and cannot grant wildcard scheduling
	// outside the channel's scope or bypass the per-user permission model.
	for _, mode := range []string{"operations", "per-user"} {
		env := shortEnv()
		env["ACCESS_MODE"] = mode
		env["MATTERMOST_CHANNEL_SCOPES"] = encode(map[string][]string{channelID: {"team-a"}})
		env["MATTERMOST_SCHEDULE_SCOPES"] = encode(map[string][]string{channelID: {"*"}})
		if _, err := NewConfig(env); err == nil {
			t.Fatal("schedule widened the channel scope", mode)
		}
		env["MATTERMOST_CHANNEL_SCOPES"] = encode(map[string][]string{channelID: {"*"}})
		if _, err := NewConfig(env); (err == nil) != (mode == "operations") {
			t.Fatal("advanced wildcard must be restricted to operations", mode, err)
		}
	}
}

func wildcardFixture(t *testing.T) (*fixture, *[]M) {
	t.Helper()
	f, _ := operationsFixture(t)
	env := f.App.S.C.Env
	delete(env, "MATTERMOST_CHANNEL_SCOPES")
	delete(env, "MATTERMOST_SCHEDULE_SCOPES")
	env["SCAN_NAMESPACES"] = "*"
	var err error
	f.App.S.C, err = NewConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	pods := []M{}
	for _, ns := range []string{"team-a", "team-b", "other-cluster"} {
		cluster := "cluster-123"
		if ns == "other-cluster" {
			cluster += "-other"
		}
		pods = append(pods, M{"id": ns, "namespace": ns, "clusterId": cluster, "deploymentId": "dep-" + ns,
			"liveInstances": []M{{"containerName": "main", "imageDigest": imageDigest}}})
	}
	original := f.Server.Config.Handler
	f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/pods":
			query := r.URL.Query().Get("query")
			if !strings.HasPrefix(query, `Cluster ID:"cluster-123"`) || strings.Contains(query, "*") {
				t.Error("wildcard must use the exact configured cluster, never Namespace:*", query)
			}
			matches := []M{}
			for _, pod := range pods {
				match := true
				for _, clause := range strings.Split(query, "+") {
					field, term, _ := strings.Cut(clause, ":")
					want, err := strconv.Unquote(term)
					if err != nil {
						t.Error("every ACS selector must use exact matching", query)
					}
					actual := map[string]string{"Cluster ID": str(pod["clusterId"]), "Namespace": str(pod["namespace"])}[field]
					match = match && actual == want
				}
				if match {
					matches = append(matches, pod)
				}
			}
			offset, _ := strconv.Atoi(r.URL.Query().Get("pagination.offset"))
			end := offset + 100
			if end > len(matches) {
				end = len(matches)
			}
			writeJSON(w, 200, M{"pods": matches[offset:end]})
			return
		case strings.HasPrefix(r.URL.Path, "/v1/deployments/dep-"):
			ns := strings.TrimPrefix(r.URL.Path, "/v1/deployments/dep-")
			writeJSON(w, 200, M{"name": "api", "namespace": ns, "clusterId": "cluster-123",
				"containers": []M{{"name": "main", "image": M{"id": imageDigest, "name": M{"fullName": "registry.acme.test/api:latest"}}}}})
			return
		}
		original.ServeHTTP(w, r)
	})
	return f, &pods
}

func TestClusterWildcardInventoryPagesAndDeduplicatesImages(t *testing.T) {
	f, pods := wildcardFixture(t)
	for i := 0; i < 100; i++ {
		*pods = append(*pods, M{"id": fmt.Sprint(i), "namespace": "team-b", "clusterId": "cluster-123", "deploymentId": "dep-team-b",
			"liveInstances": []M{{"containerName": "main", "imageDigest": imageDigest}}})
	}
	inv, err := f.App.S.Inventory(context.Background(), []string{"*"}, false)
	if err != nil || inv.Pods != 102 || len(inv.Images) != 1 || len(inv.Images[0].Targets) != 2 {
		t.Fatal("all pages and namespaces must be included; shared images scanned once", inv, err)
	}
	for _, target := range inv.Images[0].Targets {
		if target.Namespace != "team-a" && target.Namespace != "team-b" {
			t.Fatal("a different cluster leaked into the inventory", target)
		}
	}
}

func TestClusterWildcardCommandsAndSingleNamespace(t *testing.T) {
	for _, command := range []string{"scan", "scan *", "report", "CVE-2026-12345", "search CVE-2026-12345 *", "scan team-b"} {
		t.Run(command, func(t *testing.T) {
			f, _ := wildcardFixture(t)
			form := url.Values{"command": {"/cve"}, "token": {"slash-secret"}, "text": {command}, "channel_id": {channelID}, "user_id": {ownerID}}
			request := httptest.NewRequest("POST", "/slash/cve", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			f.App.ServeHTTP(response, request)
			f.App.Wait()
			if response.Code != 200 || len(f.Posts) != 1 {
				t.Fatal(response.Body.String(), f.Posts)
			}
			body := str(f.Posts[0]["message"])
			if !strings.Contains(body, "`team-b`") || strings.Contains(body, "other-cluster") || strings.Contains(body, "`team-a`") != (command != "scan team-b") {
				t.Fatal("report omitted or mixed namespace rows", body)
			}
			if f.FileUploads != 0 || f.ScanCalls+f.ImageReads != 1 || (f.ScanCalls == 1) != strings.HasPrefix(command, "scan") {
				t.Fatal("wrong scan/read mode, duplicate scan or JSON attachment", f.ScanCalls, f.ImageReads, f.FileUploads)
			}
		})
	}
}

func TestClusterWildcardRejectsUnverifiedInventory(t *testing.T) {
	for _, test := range []string{"other cluster", "missing namespace", "deployment namespace", "deployment cluster", "HTTP 403"} {
		t.Run(test, func(t *testing.T) {
			f, _ := wildcardFixture(t)
			original := f.Server.Config.Handler
			f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/pods" && test == "HTTP 403" {
					writeJSON(w, 403, M{})
					return
				}
				if r.URL.Path == "/v1/pods" {
					pod := M{"id": "pod1", "namespace": "team-a", "clusterId": "cluster-123", "deploymentId": "dep-team-a", "liveInstances": []M{{"containerName": "main", "imageDigest": imageDigest}}}
					if test == "other cluster" {
						pod["clusterId"] = "cluster-123-other"
					} else if test == "missing namespace" {
						delete(pod, "namespace")
					}
					writeJSON(w, 200, M{"pods": []M{pod}})
					return
				}
				if strings.HasPrefix(test, "deployment") && r.URL.Path == "/v1/deployments/dep-team-a" {
					dep := M{"namespace": "team-a", "clusterId": "cluster-123"}
					if test == "deployment namespace" {
						dep["namespace"] = "team-b"
					} else {
						dep["clusterId"] = "cluster-123-other"
					}
					writeJSON(w, 200, dep)
					return
				}
				original.ServeHTTP(w, r)
			})
			if _, err := f.App.S.Scan(context.Background(), []string{"*"}, func() error { return nil }, true, false); err == nil || f.ScanCalls != 0 {
				t.Fatal("unverified wildcard inventory was scanned", err, f.ScanCalls)
			}
		})
	}
}

func TestClusterWildcardRequiresExplicitOperationsGrant(t *testing.T) {
	f, _ := operationsFixture(t)
	if _, err := f.App.S.ActorAudience(context.Background(), ownerID, channelID, []string{"*"}); err == nil {
		t.Fatal("command wildcard bypassed explicit namespace list")
	}
	f, _ = wildcardFixture(t)
	if _, err := f.App.S.ActorAudience(context.Background(), strings.Repeat("z", 26), channelID, []string{"*"}); err == nil {
		t.Fatal("wildcard bypassed channel membership")
	}
	f.App.S.C.ScheduleScopes[channelID] = []string{"team-a"}
	if _, err := f.App.S.ScheduledAudience(context.Background(), channelID, []string{"*"}); err == nil {
		t.Fatal("wildcard bypassed narrower schedule scope")
	}
	if a, err := f.App.S.ScheduledAudience(context.Background(), channelID, nil); err != nil || !same(a.Namespaces, []string{"team-a"}) {
		t.Fatal("explicit schedule subset of wildcard channel failed", a, err)
	}
}

func TestClusterWildcardScheduleIncludesFutureNamespacesAndCanBeRevoked(t *testing.T) {
	f, pods := wildcardFixture(t)
	key := open(t, f)
	var optionFound bool
	for _, element := range arr(obj(f.Dialog["dialog"])["elements"]) {
		if str(obj(element)["name"]) == "namespaces" {
			for _, option := range arr(obj(element)["options"]) {
				optionFound = optionFound || str(obj(option)["value"]) == "*" && strings.Contains(str(obj(option)["text"]), "Alla namespaces")
			}
		}
	}
	if !optionFound {
		t.Fatal("schedule dialog must label the wildcard clearly")
	}
	payload := submission(key)
	obj(payload["submission"])["namespaces"] = "*"
	if err := f.App.SubmitDialog(context.Background(), key, payload); err != nil {
		t.Fatal(err)
	}
	current, err := f.App.Store.Schedule(channelID)
	if err != nil || current == nil || !allNamespaceScope(current.Config.Namespaces) {
		t.Fatal("schedule must store the dynamic selector", current, err)
	}
	*pods = append(*pods, M{"id": "new-pod", "namespace": "new-team", "clusterId": "cluster-123", "deploymentId": "dep-new-team", "liveInstances": []M{{"containerName": "main", "imageDigest": imageDigest}}})
	if err := f.App.Store.Enqueue(channelID, current.Revision); err != nil {
		t.Fatal(err)
	}
	run, err := f.App.Store.TakeRun()
	if err != nil || run == nil {
		t.Fatal(run, err)
	}
	f.Posts = nil // Ignore the confirmation that the schedule was saved.
	f.App.execute(channelID, "", "scan", current.Config.Namespaces, run)
	if len(f.Posts) != 1 || !strings.Contains(str(f.Posts[0]["message"]), "`new-team`") {
		t.Fatal("new namespace was not included by saved wildcard schedule", f.Posts)
	}
	f.App.S.C.Scopes[channelID] = []string{"team-a"}
	f.App.S.C.ScheduleScopes[channelID] = []string{"team-a"}
	if _, err := f.App.S.ScheduledAudience(context.Background(), channelID, current.Config.Namespaces); err == nil {
		t.Fatal("saved wildcard survived removal of cluster-wide permission")
	}
}
