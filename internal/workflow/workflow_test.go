package workflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func workflow(t *testing.T, values string, extra ...string) (string, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper")
	}
	_, source, _, _ := runtime.Caller(0)
	script, e := os.ReadFile(filepath.Join(filepath.Dir(source), "../../cvebridge.sh"))
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); e != nil {
			t.Fatal(e)
		}
	}
	write("cvebridge.sh", string(script), 0700)
	write(".env", values, 0600)
	write("oc", `#!/bin/sh
set -eu
printf 'oc %s\n' "$*" >> "$CALL_LOG"
case "$*" in
 'whoami') printf 'alice\n';;
 'whoami -t') printf 'TEST_ONLY_OAUTH_TOKEN\n';;
 'get project security -o name') [ "${MISSING_NAMESPACE:-0}" = 0 ];;
 'get route default-route -n openshift-image-registry -o jsonpath={.spec.host}') [ "${MISSING_ROUTE:-0}" = 0 ]; printf 'default-route-openshift-image-registry.apps.lab.test';;
 *) exit 2;;
esac
`, 0700)
	write("engine", `#!/bin/sh
set -eu
printf 'engine %s\n' "$*" >> "$CALL_LOG"
if [ "$1" = login ]; then read -r token; [ "$token" = TEST_ONLY_OAUTH_TOKEN ]; fi
`, 0700)
	command := exec.Command("sh", filepath.Join(dir, "cvebridge.sh"), "push")
	command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CONTAINER_ENGINE="+filepath.Join(dir, "engine"), "CALL_LOG="+filepath.Join(dir, "calls"))
	command.Env = append(command.Env, extra...)
	output, err := command.CombinedOutput()
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	status := "ok"
	if err != nil {
		status = "failed"
	}
	return status, string(output), string(calls)
}

func TestPushUsesRouteWhileKeepingInternalDeploymentReference(t *testing.T) {
	status, output, calls := workflow(t, "NAMESPACE=security\nIMAGE_TAG=v1\n")
	if status != "ok" {
		t.Fatal(output, calls)
	}
	for _, want := range []string{"oc get project security -o name", "engine login --username cvebridge --password-stdin default-route-openshift-image-registry.apps.lab.test", "engine tag image-registry.openshift-image-registry.svc:5000/security/cvebridge:v1 default-route-openshift-image-registry.apps.lab.test/security/cvebridge:v1", "engine push default-route-openshift-image-registry.apps.lab.test/security/cvebridge:v1"} {
		if !strings.Contains(calls, want) {
			t.Fatal("missing " + want + "\n" + calls)
		}
	}
	if strings.Contains(output+calls, "TEST_ONLY_OAUTH_TOKEN") {
		t.Fatal("OAuth token exposed in output or command arguments")
	}
}
func TestPushStopsBeforeLoginWhenNamespaceOrRouteIsMissing(t *testing.T) {
	for _, setting := range []string{"MISSING_NAMESPACE=1", "MISSING_ROUTE=1"} {
		status, _, calls := workflow(t, "NAMESPACE=security\nIMAGE_TAG=v1\n", setting)
		if status != "failed" || strings.Contains(calls, "engine push") || strings.Contains(calls, "engine login") {
			t.Fatal(setting, status, calls)
		}
	}
}
func TestRegistryOverrideDoesNotRequireRouteReadPermission(t *testing.T) {
	status, output, calls := workflow(t, "NAMESPACE=security\nIMAGE_TAG=v1\nREGISTRY_PUSH_HOST=registry.apps.corp.test\n", "MISSING_ROUTE=1")
	if status != "ok" || strings.Contains(calls, "oc get route") || !strings.Contains(calls, "engine push registry.apps.corp.test/security/cvebridge:v1") {
		t.Fatal(status, output, calls)
	}
}
func TestUnsafeAndCrossNamespaceImagesCannotBePushed(t *testing.T) {
	for _, body := range []string{"NAMESPACE=$(id)\nIMAGE_TAG=v1\n", "NAMESPACE=security\nAPP_IMAGE=$(id)\n", "NAMESPACE=security\nAPP_IMAGE=image-registry.openshift-image-registry.svc:5000/other/cvebridge:v1\n"} {
		status, _, calls := workflow(t, body)
		if status != "failed" || strings.Contains(calls, "engine push") {
			t.Fatal(status, calls)
		}
	}
}
func TestExternalRegistryOverrideRetainsExistingPushBehavior(t *testing.T) {
	status, output, calls := workflow(t, "NAMESPACE=security\nAPP_IMAGE='registry.corp.test/security/cvebridge:v1'\n")
	if status != "ok" || strings.Contains(calls, "oc ") || !strings.Contains(calls, "engine push registry.corp.test/security/cvebridge:v1") {
		t.Fatal(status, output, calls)
	}
}
