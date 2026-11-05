package setup

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const registry = "image-registry.openshift-image-registry.svc:5000/image-security/cvebridge:"

func project(t *testing.T) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	script, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../configure.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "configure.sh"), script, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func run(t *testing.T, dir string, answers []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(dir, "configure.sh")}, args...)...)
	cmd.Stdin = strings.NewReader(strings.Join(answers, "\n") + "\n")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func answers() []string {
	return []string{"", "existing-state", "team-b, team-a,team-a", "https://central.example.test/", "cluster-123",
		"acs-literal-$()-`test`", "https://mattermost.example.test", strings.Repeat("c", 26),
		"bot-literal-\"-$()-`test`", "command-literal-$()-`test`", "cvebridge.apps.lab.example.test"}
}

func object(t *testing.T, dir, filename string) map[string]any {
	t.Helper()
	path := filepath.Join(dir, "deploy", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := yaml.UnmarshalStrict(data, &value); err != nil {
		t.Fatal(filename, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("generated file must be private", filename)
	}
	return value
}

func mapping(v any) map[string]any { return v.(map[string]any) }
func list(v any) []any             { return v.([]any) }

func image(t *testing.T, dir string) string {
	t.Helper()
	deployment := object(t, dir, "deployment.yaml")
	pod := mapping(mapping(deployment["spec"])["template"])["spec"]
	return mapping(list(mapping(pod)["containers"])[0])["image"].(string)
}

func TestReadySetupWritesConsistentYAMLAndKeepsCredentialsPrivate(t *testing.T) {
	dir := project(t)
	input := answers()
	output, err := run(t, dir, input)
	if err != nil {
		t.Fatal(err, output)
	}
	for _, token := range []string{input[5], input[8], input[9]} {
		if strings.Contains(output, token) {
			t.Fatal("credential appeared in terminal output")
		}
	}
	secret := mapping(object(t, dir, "secret.yaml")["stringData"])
	if len(secret) != 3 || secret["STACKROX_TOKEN"] != input[5] || secret["MATTERMOST_BOT_TOKEN"] != input[8] {
		t.Fatal("literal secret values changed")
	}
	cm := mapping(object(t, dir, "configmap.yaml")["data"])
	if cm["SCAN_NAMESPACES"] != "team-a,team-b" || cm["MATTERMOST_DIALOG_URL"] != "https://"+input[10]+"/slash/cve/dialog" || cm["ACCESS_MODE"] != "operations" {
		t.Fatal("configuration was not completed automatically")
	}
	if _, exists := cm["MATTERMOST_KUBE_USER_MAP"]; exists {
		t.Fatal("unexpected user mapping")
	}
	fullImage := image(t, dir)
	if !strings.HasPrefix(fullImage, registry) || strings.Count(output, fullImage) != 2 {
		t.Fatal("build/tag/push and deployment must share one registry image", output)
	}
	for _, filename := range []string{"configmap.yaml", "secret.yaml", "deployment.yaml", "service.yaml", "serviceaccount.yaml", "trusted-ca.yaml", "route.yaml"} {
		obj := object(t, dir, filename)
		if mapping(obj["metadata"])["namespace"] != "image-security" {
			t.Fatal("single apply must use explicit namespaces", filename)
		}
	}
	pod := mapping(mapping(mapping(object(t, dir, "deployment.yaml")["spec"])["template"])["spec"])
	if pod["automountServiceAccountToken"] != false || mapping(object(t, dir, "serviceaccount.yaml"))["automountServiceAccountToken"] != false {
		t.Fatal("operations must not need a Kubernetes API token")
	}
	if !strings.Contains(output, "oc apply -f deploy/") {
		t.Fatal("missing single apply command")
	}
	state, _ := os.Stat(filepath.Join(dir, ".local/setup.json"))
	if state.Mode().Perm() != 0600 {
		t.Fatal("draft containing credentials must have mode 0600")
	}
}

func TestEmptyDraftCanResumeAndDoesNotLeaveRunnableYAML(t *testing.T) {
	dir := project(t)
	output, err := run(t, dir, make([]string, 11))
	if err != nil || !strings.Contains(output, "UTKAST SPARAT") || strings.Contains(output, "oc apply -f") {
		t.Fatal(err, output)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "deploy/*.yaml"))
	if len(files) != 0 {
		t.Fatal("incomplete configuration produced runnable YAML")
	}
	if _, err := run(t, dir, nil, "--check"); err == nil {
		t.Fatal("incomplete draft was marked ready")
	}
	if output, err := run(t, dir, answers()); err != nil || !strings.Contains(output, "KLAR ATT INSTALLERA") {
		t.Fatal(err, output)
	}
	clear := make([]string, 11)
	clear[1] = "-"
	if output, err := run(t, dir, clear); err != nil || !strings.Contains(output, "UTKAST SPARAT") {
		t.Fatal(err, output)
	}
	files, _ = filepath.Glob(filepath.Join(dir, "deploy/*.yaml"))
	if len(files) != 0 {
		t.Fatal("draft left stale credentials or deployment YAML")
	}
}

func TestReconfigureKeepsTagAndSecretsUnlessNewTagIsRequested(t *testing.T) {
	dir := project(t)
	if output, err := run(t, dir, answers()); err != nil {
		t.Fatal(err, output)
	}
	before := image(t, dir)
	if output, err := run(t, dir, make([]string, 11)); err != nil || !strings.Contains(output, "[sparad]") {
		t.Fatal(err, output)
	}
	if image(t, dir) != before {
		t.Fatal("changing configuration must not change the image tag")
	}
	if output, err := run(t, dir, nil, "--check"); err != nil || strings.Contains(output, "acs-literal") {
		t.Fatal(err, output)
	}
	if err := os.Remove(filepath.Join(dir, "deploy/deployment.yaml")); err != nil {
		t.Fatal(err)
	}
	if output, err := run(t, dir, nil, "--check"); err == nil || !strings.Contains(output, "behöver uppdateras") {
		t.Fatal("missing YAML was marked ready", output)
	}
	if output, err := run(t, dir, make([]string, 11), "--new-tag"); err != nil {
		t.Fatal(err, output)
	}
	if image(t, dir) == before {
		t.Fatal("new program version needs a new automatic tag")
	}
}

func TestCommandTokenAndRouteCanBeDeferred(t *testing.T) {
	dir := project(t)
	input := answers()
	input[9], input[10] = "", ""
	output, err := run(t, dir, input)
	if err != nil || !strings.Contains(output, "kommandon väntar") || !strings.Contains(output, "oc apply -f deploy/") {
		t.Fatal(err, output)
	}
	if _, err := os.Stat(filepath.Join(dir, "deploy/route.yaml")); !os.IsNotExist(err) {
		t.Fatal("empty route host produced an invalid route")
	}
	if mapping(object(t, dir, "secret.yaml")["stringData"])["MATTERMOST_COMMAND_TOKEN"] != "" {
		t.Fatal("missing token was invented")
	}
}

func TestAlternateNamespaceGetsOnlyImagePullAccess(t *testing.T) {
	dir := project(t)
	input := answers()
	input[0] = "security-tools"
	if output, err := run(t, dir, input); err != nil {
		t.Fatal(err, output)
	}
	binding := object(t, dir, "image-puller.yaml")
	if mapping(binding["metadata"])["namespace"] != "image-security" || mapping(binding["roleRef"])["name"] != "system:image-puller" || mapping(list(binding["subjects"])[0])["namespace"] != "security-tools" {
		t.Fatal("cross-namespace image pull binding is incorrect")
	}
	if !strings.HasPrefix(image(t, dir), registry) {
		t.Fatal("image namespace must stay image-security")
	}
}

func TestInvalidSavedConfigurationDoesNotOverwriteFilesOrRevealTokens(t *testing.T) {
	dir := project(t)
	if output, err := run(t, dir, answers()); err != nil {
		t.Fatal(err, output)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "deploy/secret.yaml"))
	path := filepath.Join(dir, ".local/setup.json")
	data, _ := os.ReadFile(path)
	var state map[string]any
	_ = json.Unmarshal(data, &state)
	state["namespace"] = "$(touch owned)"
	data, _ = json.Marshal(state)
	_ = os.WriteFile(path, data, 0600)
	output, err := run(t, dir, nil, "--check")
	if err == nil || strings.Contains(output, "acs-literal") || strings.Contains(output, "$(touch") {
		t.Fatal("invalid draft accepted or sensitive contents printed", output)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "deploy/secret.yaml"))
	if string(before) != string(after) {
		t.Fatal("validation failure changed previous installation")
	}
}
