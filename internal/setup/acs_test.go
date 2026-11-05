package setup

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func acsDiagnostic(t *testing.T, server *httptest.Server, trust bool) (string, error) {
	t.Helper()
	dir := project(t)
	local := filepath.Join(dir, ".local")
	if err := os.Mkdir(local, 0700); err != nil {
		t.Fatal(err)
	}
	const token = "private-acs-token-$()-literal"
	state, _ := json.Marshal(map[string]string{"acs_url": server.URL, "acs_token": token})
	statePath := filepath.Join(local, "setup.json")
	if err := os.WriteFile(statePath, state, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(statePath)
	ca := filepath.Join(dir, "test-ca.crt")
	var cert []byte
	if trust {
		cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	}
	if err := os.WriteFile(ca, cert, 0600); err != nil {
		t.Fatal(err)
	}
	emptyCAs := filepath.Join(dir, "empty-cas")
	if err := os.Mkdir(emptyCAs, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(dir, "configure.sh"), "--test-acs")
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR":
			continue
		}
		cmd.Env = append(cmd.Env, pair)
	}
	cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+emptyCAs, "NO_PROXY=*")
	output, err := cmd.CombinedOutput()
	after, _ := os.Stat(statePath)
	saved, _ := os.ReadFile(statePath)
	if string(saved) != string(state) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("diagnostic changed the saved configuration")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "deploy")); !os.IsNotExist(statErr) {
		t.Fatal("diagnostic must work with only ACS settings and create no deployment files")
	}
	if strings.Contains(string(output), token) {
		t.Fatal("diagnostic revealed its token or an upstream response body")
	}
	return string(output), err
}

func TestACSDiagnosticChecksRealHTTPSResponsesAndPreservesSavedSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
		want string
		ok   bool
	}{
		{"allowed", 200, `{"lastUpdatedTimestamp":"2026-11-05T12:00:00Z"}`, "Åtkomst fungerar", true},
		{"forbidden", 403, `{"message":"private-acs-token-$()-literal"}`, "Administration: Read", false},
		{"unauthorized", 401, `{}`, "Tokenen godkändes inte", false},
		{"html-login-page", 200, `<html>private-acs-token-$()-literal</html>`, "kunde inte verifieras", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer private-acs-token-$()-literal" {
					t.Error("expected a read-only request authenticated with the saved token")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/metadata":
					_, _ = io.WriteString(w, `{"version":"test"}`)
				case "/v1/integrationhealth/vulndefinitions":
					if r.URL.Query().Get("component") != "SCANNER_V4" {
						t.Error("must test the same scanner as the bot")
					}
					w.WriteHeader(tc.code)
					_, _ = io.WriteString(w, tc.body)
				default:
					t.Errorf("unexpected API path: %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			output, err := acsDiagnostic(t, server, true)
			if (err == nil) != tc.ok || !strings.Contains(output, tc.want) || calls.Load() != 2 {
				t.Fatal(err, output, "requests:", calls.Load())
			}
		})
	}
}

func TestACSDiagnosticNeverForwardsTokenOnRedirect(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(200)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	output, err := acsDiagnostic(t, server, true)
	if err == nil || !strings.Contains(output, "Ingen omdirigering följdes") || redirected.Load() != 0 {
		t.Fatal(err, output, "redirected requests:", redirected.Load())
	}
}

func TestACSDiagnosticRejectsUntrustedCertificates(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	output, err := acsDiagnostic(t, server, false)
	if err == nil || !strings.Contains(output, "Certifikatfel") || calls.Load() != 0 {
		t.Fatal(err, output, "authenticated requests:", calls.Load())
	}
}
