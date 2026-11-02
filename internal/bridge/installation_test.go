package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestSharedACSTokenAndExplicitOverrides(t *testing.T) {
	for _, separate := range []bool{false, true} {
		env := shortEnv()
		env["STACKROX_TOKEN"] = "shared-acs-credential"
		for _, key := range []string{"STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"} {
			delete(env, key)
			if separate {
				env[key] = "explicit-" + key
			}
		}
		authorization := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization <- r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(server.Close)
		env["STACKROX_URL"] = server.URL
		config, err := NewConfig(env)
		if err != nil {
			t.Fatal(err)
		}
		services := &Services{C: config, Rox: server.Client()}
		for _, request := range []struct {
			cap, key  string
			scheduled bool
		}{{"read", "STACKROX_TOKEN", false}, {"scan", "STACKROX_SCAN_TOKEN", false}, {"status", "STACKROX_STATUS_TOKEN", false}, {"read", "STACKROX_SCHEDULE_TOKEN", true}, {"scan", "STACKROX_SCHEDULE_TOKEN", true}} {
			if _, err := services.RoxRequest(context.Background(), "/test", request.cap, nil, request.scheduled); err != nil {
				t.Fatal(err)
			}
			want := "shared-acs-credential"
			if separate && request.key != "STACKROX_TOKEN" {
				want = "explicit-" + request.key
			}
			if <-authorization != "Bearer "+want {
				t.Fatal("incorrect ACS credential selected")
			}
		}
		resources := storageResources(t, env, "deployment")
		secret := obj(resources["Secret/cvebridge-integration"]["stringData"])
		for _, key := range []string{"STACKROX_TOKEN", "STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"} {
			if secret[key] != config.Get(key, "") {
				t.Fatal("effective token missing from generated Secret")
			}
		}
		if !separate && env["STACKROX_SCAN_TOKEN"] != "" {
			t.Fatal("caller input was mutated")
		}
	}
}

func TestSharedTokenPreservesExplicitCredentialFailures(t *testing.T) {
	for _, key := range []string{"STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"} {
		for _, invalid := range []string{"", "CHANGE_ME"} {
			env := shortEnv()
			env[key] = invalid
			if err := Render(&bytes.Buffer{}, env, "deployment"); err == nil {
				t.Fatal("explicit incomplete override must not fall back to a broader token")
			}
		}
	}
}

func TestManifestYAMLSeparatesBootstrapAndKeepsSecretsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deploy")
	env := shortEnv()
	if err := RenderManifests(dir, env); err != nil {
		t.Fatal(err)
	}
	// Switching to an existing claim and internal service must remove old optional
	// outputs, otherwise applying the directory would recreate them.
	env["STATE_EXISTING_PVC"] = "existing-company-pvc"
	delete(env, "WEBHOOK_PUBLIC_URL")
	env["MATTERMOST_BOT_TOKEN"] = "true: literal $()`"
	if err := RenderManifests(dir, env); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"route.yaml", "pvc.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, "app", name)); !os.IsNotExist(err) {
			t.Fatal("old optional resource would be applied again")
		}
	}
	got := map[string]M{}
	files, err := filepath.Glob(filepath.Join(dir, "app", "*.yaml"))
	if err != nil || len(files) != 5 {
		t.Fatal(files, err)
	}
	files = append(files, filepath.Join(dir, "bootstrap.yaml"))
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("generated manifest must have mode 0600", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasPrefix(data, []byte("{")) {
			t.Fatal("expected readable YAML, not a JSON List")
		}
		for _, document := range bytes.Split(data, []byte("---\n")) {
			var item M
			if err := yaml.UnmarshalStrict(document, &item); err != nil {
				t.Fatal(err)
			}
			kind := str(item["kind"])
			if filepath.Base(path) == "bootstrap.yaml" {
				if kind == "Secret" || kind == "Deployment" || kind == "Service" {
					t.Fatal("application resource in cluster bootstrap")
				}
			} else if kind == "ClusterRole" || kind == "ClusterRoleBinding" || kind == "Namespace" || kind == "PersistentVolume" {
				t.Fatal("app directory would require cluster admin")
			}
			if kind != "Secret" && strings.Contains(string(document), "true: literal") {
				t.Fatal("credentials outside Secret")
			}
			got[kind+"/"+str(obj(item["metadata"])["name"])] = item
		}
	}
	for _, part := range []string{"bootstrap", "deployment"} {
		for key, expected := range storageResources(t, env, part) {
			if !same(expected, got[key]) {
				t.Fatal("YAML changed the resource semantics", key)
			}
		}
	}
	if obj(got["Secret/cvebridge-integration"]["stringData"])["MATTERMOST_BOT_TOKEN"] != env["MATTERMOST_BOT_TOKEN"] {
		t.Fatal("YAML interpreted a token as another value")
	}
}

func TestInvalidManifestConfigurationPreservesPreviousOutput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deploy")
	env := shortEnv()
	if err := RenderManifests(dir, env); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "app", "secret.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env["MATTERMOST_KUBE_USER_MAP"] = "invalid-json"
	if err := RenderManifests(dir, env); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("previous manifests changed after a validation failure")
	}
	var dummy any
	if json.Unmarshal(before, &dummy) == nil {
		t.Fatal("expected ordinary YAML")
	}
}
