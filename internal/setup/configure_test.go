package setup

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	return runWithRegistry(t, dir, "", answers, args...)
}

func runWithRegistry(t *testing.T, dir, address string, answers []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(dir, "configure.sh")}, args...)...)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "REGISTRY=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	if address != "" {
		cmd.Env = append(cmd.Env, "REGISTRY="+address)
	}
	cmd.Stdin = strings.NewReader(strings.Join(answers, "\n") + "\n")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func answers() []string {
	return []string{"", "existing-state", "team-b, team-a,team-a", "https://central.example.test/", "cluster-123",
		"acs-literal-$()-`test`", "https://mattermost.example.test", strings.Repeat("c", 26),
		"bot-literal-\"-$()-`test`", "command-literal-$()-`test`", "cvebridge.apps.lab.example.test"}
}

func TestSetupAcceptsClusterWildcardAndRejectsMixedScopes(t *testing.T) {
	dir := project(t)
	input := answers()
	input[2] = "*"
	if output, err := run(t, dir, input); err != nil {
		t.Fatal(err, output)
	}
	cm := mapping(object(t, dir, "configmap.yaml")["data"])
	if cm["SCAN_NAMESPACES"] != "*" || cm["STACKROX_CLUSTER_ID"] != input[4] {
		t.Fatal("wildcard must preserve the explicitly chosen cluster", cm)
	}
	if output, err := run(t, dir, nil, "--check"); err != nil {
		t.Fatal(err, output)
	}
	for _, scope := range []string{"*,team-a", "team-*", "*,*"} {
		badDir := project(t)
		badInput := answers()
		badInput[2] = scope
		// The following answer supplies a valid replacement after the error.
		badInput = append(badInput[:3], append([]string{"*"}, badInput[3:]...)...)
		output, err := run(t, badDir, badInput)
		if err != nil || !strings.Contains(output, "endast *") {
			t.Fatal("invalid glob or mixed scope was not rejected", scope, err, output)
		}
	}
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
	deployment := object(t, dir, "z-deployment.yaml")
	pod := mapping(mapping(deployment["spec"])["template"])["spec"]
	return mapping(list(mapping(pod)["containers"])[0])["image"].(string)
}

func revision(t *testing.T, dir string) any {
	t.Helper()
	template := mapping(mapping(object(t, dir, "z-deployment.yaml")["spec"])["template"])
	return mapping(mapping(template["metadata"])["annotations"])["cvebridge/setup-revision"]
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
	if cm["SENSOR_MONITOR_ENABLED"] != "true" || cm["DATABASE_MONITOR_CHANNEL_ID"] != input[7] || cm["STACKROX_CLUSTER_ID"] != input[4] {
		t.Fatal("sensor monitoring must reuse the existing cluster and ops channel without new prompts")
	}
	fullImage := image(t, dir)
	if fullImage != registry+"latest" || !strings.Contains(output, `podman tag localhost/cvebridge:latest "$REGISTRY/image-security/cvebridge:latest"`) || !strings.Contains(output, `podman push "$REGISTRY/image-security/cvebridge:latest"`) {
		t.Fatal("build/tag/push and deployment must share one registry image", output)
	}
	for _, filename := range []string{"configmap.yaml", "secret.yaml", "z-deployment.yaml", "service.yaml", "serviceaccount.yaml", "trusted-ca.yaml", "route.yaml"} {
		obj := object(t, dir, filename)
		if mapping(obj["metadata"])["namespace"] != "image-security" {
			t.Fatal("single apply must use explicit namespaces", filename)
		}
	}
	pod := mapping(mapping(mapping(object(t, dir, "z-deployment.yaml")["spec"])["template"])["spec"])
	if mapping(list(pod["containers"])[0])["imagePullPolicy"] != "Always" {
		t.Fatal("latest must resolve the current registry image at each container start")
	}
	if pod["automountServiceAccountToken"] != false || mapping(object(t, dir, "serviceaccount.yaml"))["automountServiceAccountToken"] != false {
		t.Fatal("operations must not need a Kubernetes API token")
	}
	if !strings.Contains(output, "oc apply -f deploy/") {
		t.Fatal("missing single apply command")
	}
	if !strings.Contains(output, "podman build --network=none") || strings.Contains(output, "go build ") || strings.Contains(output, "mkdir -p bin/") {
		t.Fatal("Podman must compile the source without a separate local Go build", output)
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
	// The namespace was already saved in the draft and must not be asked again.
	if output, err := run(t, dir, answers()[1:]); err != nil || !strings.Contains(output, "KLAR ATT INSTALLERA") {
		t.Fatal(err, output)
	}
	clear := make([]string, 11)
	clear[1] = "-"
	if output, err := run(t, dir, clear, "--edit"); err != nil || !strings.Contains(output, "UTKAST SPARAT") {
		t.Fatal(err, output)
	}
	files, _ = filepath.Glob(filepath.Join(dir, "deploy/*.yaml"))
	if len(files) != 0 {
		t.Fatal("draft left stale credentials or deployment YAML")
	}
}

func TestReconfigureKeepsLatestAndSecretsAndPreparesRequestedRollout(t *testing.T) {
	dir := project(t)
	if output, err := run(t, dir, answers()); err != nil {
		t.Fatal(err, output)
	}
	before := image(t, dir)
	beforeRevision := revision(t, dir)
	if output, err := run(t, dir, nil); err != nil || !strings.Contains(output, "Inga frågor behövs") {
		t.Fatal(err, output)
	}
	if image(t, dir) != before {
		t.Fatal("changing configuration must not change the image tag")
	}
	if revision(t, dir) != beforeRevision {
		t.Fatal("unchanged answers must not restart the pod")
	}
	changed := make([]string, 11)
	changed[9] = "new-command-credential"
	if output, err := run(t, dir, changed, "--edit"); err != nil {
		t.Fatal(err, output)
	}
	if revision(t, dir) == beforeRevision || image(t, dir) != before {
		t.Fatal("token update must trigger rollout without an image rebuild")
	}
	if output, err := run(t, dir, nil, "--check"); err != nil || strings.Contains(output, "acs-literal") {
		t.Fatal(err, output)
	}
	beforeUpdate := revision(t, dir)
	if err := os.Remove(filepath.Join(dir, "deploy/z-deployment.yaml")); err != nil {
		t.Fatal(err)
	}
	if output, err := run(t, dir, nil, "--check"); err == nil || !strings.Contains(output, "behöver uppdateras") {
		t.Fatal("missing YAML was marked ready", output)
	}
	secretBefore, _ := os.ReadFile(filepath.Join(dir, "deploy/secret.yaml"))
	configBefore, _ := os.ReadFile(filepath.Join(dir, "deploy/configmap.yaml"))
	if output, err := run(t, dir, nil, "--update-image"); err != nil || !strings.Contains(output, "Inga frågor behövs") {
		t.Fatal(err, output)
	}
	if image(t, dir) != before || revision(t, dir) == beforeUpdate {
		t.Fatal("an image update must change the pod template while keeping :latest")
	}
	secretAfter, _ := os.ReadFile(filepath.Join(dir, "deploy/secret.yaml"))
	configAfter, _ := os.ReadFile(filepath.Join(dir, "deploy/configmap.yaml"))
	if string(secretBefore) != string(secretAfter) || string(configBefore) != string(configAfter) {
		t.Fatal("preparing a latest rollout changed company settings")
	}
	beforeAlias := revision(t, dir)
	if output, err := run(t, dir, nil, "--new-tag"); err != nil || image(t, dir) != before || revision(t, dir) == beforeAlias {
		t.Fatal("legacy --new-tag must prepare a rollout with the same latest tag", err, output)
	}
}

func TestExistingVersionedSetupMigratesToLatestWithoutReenteringValues(t *testing.T) {
	dir := project(t)
	if output, err := run(t, dir, answers()); err != nil {
		t.Fatal(err, output)
	}
	statePath := filepath.Join(dir, ".local/setup.json")
	data, _ := os.ReadFile(statePath)
	var state map[string]any
	_ = json.Unmarshal(data, &state)
	state["tag"] = "20261106-092027-2870"
	data, _ = json.Marshal(state)
	_ = os.WriteFile(statePath, data, 0600)
	deploymentPath := filepath.Join(dir, "deploy/z-deployment.yaml")
	deployment, _ := os.ReadFile(deploymentPath)
	oldDeployment := strings.ReplaceAll(strings.ReplaceAll(string(deployment), ":latest", ":20261106-092027-2870"), `"Always"`, `"IfNotPresent"`)
	_ = os.WriteFile(deploymentPath, []byte(oldDeployment), 0600)
	secretBefore, _ := os.ReadFile(filepath.Join(dir, "deploy/secret.yaml"))
	// Check identifies the necessary migration without modifying either file.
	if output, err := run(t, dir, nil, "--check"); err == nil || !strings.Contains(output, "behöver uppdateras") {
		t.Fatal("old versioned deployment was marked ready", output)
	}
	unchanged, _ := os.ReadFile(deploymentPath)
	if string(unchanged) != oldDeployment {
		t.Fatal("check changed the existing Deployment")
	}
	if output, err := run(t, dir, nil); err != nil || !strings.Contains(output, "Inga frågor behövs") {
		t.Fatal("migration asked for already-saved company values", err, output)
	}
	data, _ = os.ReadFile(statePath)
	_ = json.Unmarshal(data, &state)
	secretAfter, _ := os.ReadFile(filepath.Join(dir, "deploy/secret.yaml"))
	if state["tag"] != "latest" || image(t, dir) != registry+"latest" || string(secretBefore) != string(secretAfter) {
		t.Fatal("latest migration changed company credentials or retained a versioned image")
	}
	if output, err := run(t, dir, nil, "--check"); err != nil {
		t.Fatal(err, output)
	}
}

func TestResumePromptsOnlyForMissingValuesAndKeepsExistingFiles(t *testing.T) {
	dir := project(t)
	input := answers()
	input[9], input[10] = "", ""
	if output, err := run(t, dir, input); err != nil {
		t.Fatal(err, output)
	}
	beforeImage, beforeRevision := image(t, dir), revision(t, dir)
	cmPath := filepath.Join(dir, "deploy/configmap.yaml")
	cmBefore, _ := os.Stat(cmPath)
	if err := os.WriteFile(filepath.Join(dir, "deploy/custom-file.yaml"), []byte("keep this file"), 0600); err != nil {
		t.Fatal(err)
	}
	// The only two missing fields get exactly two answers, with no replay of
	// namespace, PVC, addresses or existing tokens.
	output, err := run(t, dir, []string{"new-command-token", "cvebridge.apps.lab.example.test"})
	if err != nil || !strings.Contains(output, "Token för /cve") || strings.Contains(output, "ACS API-token:") || strings.Contains(output, "Namespace för boten [") {
		t.Fatal("filled fields must be skipped", err, output)
	}
	secret := mapping(object(t, dir, "secret.yaml")["stringData"])
	if secret["STACKROX_TOKEN"] != input[5] || secret["MATTERMOST_BOT_TOKEN"] != input[8] || secret["MATTERMOST_COMMAND_TOKEN"] != "new-command-token" || image(t, dir) != beforeImage || revision(t, dir) == beforeRevision {
		t.Fatal("resuming lost existing settings or failed to update the missing ones")
	}
	if contents, _ := os.ReadFile(filepath.Join(dir, "deploy/custom-file.yaml")); string(contents) != "keep this file" {
		t.Fatal("unrelated files in the existing deploy directory were changed")
	}
	cmAfter, _ := os.Stat(cmPath)
	if cmAfter.ModTime() == cmBefore.ModTime() {
		t.Fatal("the newly added Route must also update the dialog address")
	}
	// A complete rerun accepts no input and leaves unchanged YAML alone.
	if output, err := run(t, dir, nil); err != nil || !strings.Contains(output, "Inga frågor behövs") {
		t.Fatal(err, output)
	}
	cmUnchanged, _ := os.Stat(cmPath)
	if !cmUnchanged.ModTime().Equal(cmAfter.ModTime()) {
		t.Fatal("a complete unchanged setup rewrote YAML unnecessarily")
	}
}

func TestRegistryVariableIsSavedAndUsedByPrintedShellCommands(t *testing.T) {
	dir := project(t)
	output, err := runWithRegistry(t, dir, "REGISTRY.EXAMPLE.TEST:5000", answers())
	if err != nil {
		t.Fatal(err, output)
	}
	fullImage := image(t, dir)
	if !strings.HasPrefix(fullImage, "registry.example.test:5000/image-security/cvebridge:") {
		t.Fatal("Deployment must use the selected registry", fullImage)
	}
	// Execute the printed block with fake tools, proving that the only user
	// variable, REGISTRY, expands to the same target as the Deployment.
	for _, variable := range regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`).FindAllString(output, -1) {
		if variable != "$REGISTRY" {
			t.Fatal("only REGISTRY should need variable expansion", variable)
		}
	}
	tools := filepath.Join(dir, "tools")
	if err := os.Mkdir(tools, 0700); err != nil {
		t.Fatal(err)
	}
	logger := `#!/usr/bin/env python3
import json, os, pathlib, sys
tool = pathlib.Path(sys.argv[0]).name
with open(os.environ['CVE_COMMAND_LOG'], 'a') as f:
    f.write(json.dumps([tool] + sys.argv[1:]) + '\n')
if tool == 'oc' and sys.argv[1:3] == ['whoami', '-t']:
    print('test-only-login-token')
elif tool == 'podman' and sys.argv[1] == 'login':
    assert sys.stdin.read().strip() == 'test-only-login-token'
`
	for _, name := range []string{"podman", "oc"} {
		if err := os.WriteFile(filepath.Join(tools, name), []byte(logger), 0700); err != nil {
			t.Fatal(err)
		}
	}
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		for _, prefix := range []string{"REGISTRY=", "podman ", "oc "} {
			if strings.HasPrefix(line, prefix) {
				lines = append(lines, line)
				break
			}
		}
	}
	logPath := filepath.Join(dir, "commands.jsonl")
	cmd := exec.Command("bash", "-eu", "-o", "pipefail", "-c", strings.Join(lines, "\n"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+tools+string(os.PathListSeparator)+os.Getenv("PATH"), "CVE_COMMAND_LOG="+logPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("printed commands could not be executed", err, string(output))
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var pushed, tagged, loggedIn bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var args []string
		if err := json.Unmarshal([]byte(line), &args); err != nil {
			t.Fatal(err)
		}
		if len(args) >= 3 && args[0] == "podman" {
			switch args[1] {
			case "push":
				pushed = args[2] == fullImage
			case "tag":
				tagged = args[3] == fullImage
			case "login":
				loggedIn = args[2] == "registry.example.test:5000"
			}
		}
	}
	if !pushed || !tagged || !loggedIn {
		t.Fatal("printed commands did not use the Deployment registry and tag", string(data))
	}
	if output, err := run(t, dir, nil); err != nil || !strings.Contains(output, "REGISTRY=registry.example.test:5000") || image(t, dir) != fullImage {
		t.Fatal("a subsequent run forgot the selected registry", err, output)
	}
}

func TestInvalidRegistryDoesNotOverwriteExistingConfiguration(t *testing.T) {
	dir := project(t)
	if output, err := run(t, dir, answers()); err != nil {
		t.Fatal(err, output)
	}
	path := filepath.Join(dir, "deploy/secret.yaml")
	before, _ := os.ReadFile(path)
	for _, address := range []string{"https://registry.example.test", "registry.example.test/project", "$(touch owned)", "host:99999", "user:password@host"} {
		output, err := runWithRegistry(t, dir, address, nil)
		if err == nil || !strings.Contains(output, "Ogiltig REGISTRY") || strings.Contains(output, "acs-literal") {
			t.Fatal("unsafe registry accepted or credentials leaked", output)
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Fatal("invalid registry changed an existing installation")
		}
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
