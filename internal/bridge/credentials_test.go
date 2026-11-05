package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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
		if !separate && env["STACKROX_SCAN_TOKEN"] != "" {
			t.Fatal("caller input was mutated")
		}
	}
}
