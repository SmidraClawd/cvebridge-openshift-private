package bridge

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func storageResources(t *testing.T, env map[string]string, part string) map[string]M {
	t.Helper()
	var out bytes.Buffer
	if err := Render(&out, env, part); err != nil {
		t.Fatal(err)
	}
	var list M
	if err := json.Unmarshal(out.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	resources := map[string]M{}
	for _, value := range arr(list["items"]) {
		r := obj(value)
		resources[str(r["kind"])+"/"+str(obj(r["metadata"])["name"])] = r
	}
	return resources
}

func TestExistingPVCIsMountedWithoutManagingStorage(t *testing.T) {
	for _, claim := range []string{"cvebridge-state", "company-data.v1"} {
		env := shortEnv()
		env["STATE_EXISTING_PVC"] = claim
		for _, part := range []string{"bootstrap", "deployment"} {
			resources := storageResources(t, env, part)
			for _, r := range resources {
				if r["kind"] == "PersistentVolume" || r["kind"] == "PersistentVolumeClaim" || r["kind"] == "Secret" && obj(r["metadata"])["name"] != "cvebridge-integration" {
					t.Fatal("existing storage must not be created, patched or given a new Secret")
				}
			}
			if part == "deployment" {
				spec := obj(resources["Deployment/cvebridge"]["spec"])
				pod := obj(obj(spec["template"])["spec"])
				container := obj(arr(pod["containers"])[0])
				if !same(pod["volumes"], []any{M{"name": "data", "persistentVolumeClaim": M{"claimName": claim}}}) || !same(container["volumeMounts"], []any{M{"name": "data", "mountPath": "/data"}}) {
					t.Fatal("Deployment must mount the specified PVC at /data")
				}
				if obj(resources["Deployment/cvebridge"]["metadata"])["namespace"] != env["NAMESPACE"] || num(spec["replicas"]) != 1 || obj(spec["strategy"])["type"] != "Recreate" {
					t.Fatal("claim namespace or single-writer policy changed")
				}
				config := obj(resources["ConfigMap/cvebridge-config"]["data"])
				if config["STATE_FILE"] != "/data/requests.sqlite3" || config["STATE_EXISTING_PVC"] != nil {
					t.Fatal("the application only needs its mounted database path")
				}
			}
		}
	}
}

func TestExistingPVCRejectsInvalidNamesAndConflictingSettings(t *testing.T) {
	cases := []map[string]string{}
	for _, name := range []string{"CHANGE_ME", "other-namespace/claim", "../claim", "UPPERCASE", "claim..name", "-claim", "claim-", strings.Repeat("a", 64), strings.Repeat("a.", 127) + "ab"} {
		cases = append(cases, map[string]string{"STATE_EXISTING_PVC": name})
	}
	for key, value := range map[string]string{
		"STATE_NETWORK_URL": "//files.lab.test/bot-state", "STORAGE_CLASS": "cephfs", "STATE_STORAGE_SIZE": "2Gi",
		"STATE_SMB_USERNAME": "user", "STATE_SMB_PASSWORD": "TEST_ONLY_PASSWORD", "STATE_SMB_DOMAIN": "domain", "STATE_SMB_SECRET": "some-secret", "STATE_SMB_GID": "0",
	} {
		cases = append(cases, map[string]string{"STATE_EXISTING_PVC": "existing-data", key: value})
	}
	for i, input := range cases {
		env := shortEnv()
		for k, v := range input {
			env[k] = v
		}
		for _, part := range []string{"bootstrap", "deployment"} {
			var out bytes.Buffer
			err := Render(&out, env, part)
			if err == nil || out.Len() != 0 {
				t.Fatalf("case %d: invalid or ambiguous claim configuration accepted", i)
			}
			if strings.Contains(err.Error(), "TEST_ONLY_PASSWORD") {
				t.Fatal("unused storage credentials leaked in error")
			}
		}
	}
}

func TestNetworkStorageBindsOnlyItsOwnRetainedPV(t *testing.T) {
	for _, source := range []string{`\\files.lab.test\bot-state\cvebridge`, "smb://files.lab.test/bot-state/cvebridge", "//files.lab.test/bot-state/cvebridge", "nfs://storage.lab.test/exports/cvebridge", "storage.lab.test:/exports/cvebridge"} {
		t.Run(source, func(t *testing.T) {
			env := shortEnv()
			env["STATE_NETWORK_URL"] = source
			env["STATE_STORAGE_SIZE"] = "2Gi"
			bootstrap := storageResources(t, env, "bootstrap")
			deployment := storageResources(t, env, "deployment")
			name := "cvebridge-security-bot-state"
			pv := bootstrap["PersistentVolume/"+name]
			if pv == nil || deployment["PersistentVolume/"+name] != nil {
				t.Fatal("PV must only be in administrator bootstrap")
			}
			if _, ok := obj(pv["metadata"])["namespace"]; ok {
				t.Fatal("PV is cluster-scoped")
			}
			spec := obj(pv["spec"])
			if spec["persistentVolumeReclaimPolicy"] != "Retain" || spec["storageClassName"] != "" || obj(spec["capacity"])["storage"] != "2Gi" {
				t.Fatal("unsafe reclaim policy, class or capacity")
			}
			ref := obj(spec["claimRef"])
			if ref["namespace"] != "security-bot" || ref["name"] != "cvebridge-state" {
				t.Fatal("PV not reserved for this claim")
			}
			pvc := obj(deployment["PersistentVolumeClaim/cvebridge-state"]["spec"])
			if pvc["storageClassName"] != "" || pvc["volumeName"] != name || obj(obj(pvc["resources"])["requests"])["storage"] != "2Gi" {
				t.Fatal("PVC could bind to default dynamic storage")
			}
			if strings.Contains(source, "nfs:") || strings.Contains(source, ":/") && !strings.Contains(source, "://") {
				if !same(spec["nfs"], M{"server": "storage.lab.test", "path": "/exports/cvebridge"}) {
					t.Fatal("wrong NFS export")
				}
			} else {
				csi := obj(spec["csi"])
				if csi["driver"] != "smb.csi.k8s.io" || csi["volumeHandle"] != "files.lab.test#cvebridge#bot-state" || !same(csi["volumeAttributes"], M{"source": "//files.lab.test/bot-state", "subDir": "cvebridge"}) || !same(csi["nodeStageSecretRef"], M{"name": "cvebridge-storage", "namespace": "security-bot"}) {
					t.Fatal("wrong SMB share, subdirectory or credentials reference")
				}
			}
			d := obj(deployment["Deployment/cvebridge"]["spec"])
			pod := obj(obj(d["template"])["spec"])
			container := obj(arr(pod["containers"])[0])
			if num(d["replicas"]) != 1 || obj(d["strategy"])["type"] != "Recreate" || !same(pod["volumes"], []any{M{"name": "data", "persistentVolumeClaim": M{"claimName": "cvebridge-state"}}}) || !same(container["volumeMounts"], []any{M{"name": "data", "mountPath": "/data"}}) {
				t.Fatal("database mount or single-writer deployment changed")
			}
			config := obj(deployment["ConfigMap/cvebridge-config"]["data"])
			if config["STATE_FILE"] != "/data/requests.sqlite3" || config["STATE_NETWORK_URL"] != nil {
				t.Fatal("SQLite must use a mounted local path")
			}
		})
	}
}

func TestSMBCredentialsAreSeparatedFromBotAndBootstrap(t *testing.T) {
	env, err := ReadEnv(strings.NewReader("STATE_NETWORK_URL='\\\\files.lab.test\\bot-state'\nSTATE_SMB_USERNAME='LAB\\bot'\nSTATE_SMB_PASSWORD='literal-$()-`password`'\nSTATE_SMB_DOMAIN=LAB\nSTATE_SMB_GID=1000770000\n"))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range shortEnv() {
		env[k] = v
	}
	env["STATE_SMB_SECRET"] = "company-storage"
	deployment := storageResources(t, env, "deployment")
	bootstrap := storageResources(t, env, "bootstrap")
	secret := obj(deployment["Secret/company-storage"]["stringData"])
	if !same(secret, M{"username": `LAB\bot`, "password": "literal-$()-`password`", "domain": "LAB"}) {
		t.Fatal("credentials were not preserved as literal data")
	}
	for name, r := range deployment {
		if name != "Secret/company-storage" && (strings.Contains(encode(r), "literal-$()") || strings.Contains(encode(r), "STATE_SMB_")) {
			t.Fatal("storage credentials reached the bot or another resource")
		}
	}
	if strings.Contains(encode(bootstrap), "literal-$()") || bootstrap["Secret/company-storage"] != nil {
		t.Fatal("credentials leaked to cluster bootstrap")
	}
	pv := obj(bootstrap["PersistentVolume/cvebridge-security-bot-state"]["spec"])
	if !has(stringsOf(pv["mountOptions"]), "gid=1000770000") || has(stringsOf(pv["mountOptions"]), "nobrl") {
		t.Fatal("group mapping or remote locking is incorrect")
	}
	delete(env, "STATE_SMB_USERNAME")
	delete(env, "STATE_SMB_PASSWORD")
	delete(env, "STATE_SMB_DOMAIN")
	if storageResources(t, env, "deployment")["Secret/company-storage"] != nil {
		t.Fatal("existing storage Secret must not be overwritten")
	}
}

func TestNetworkStorageRejectsInvalidInputsWithoutLeakingThem(t *testing.T) {
	cases := []map[string]string{}
	for _, source := range []string{"https://files.lab.test/share", "smb://user:private-password@files.lab.test/share", "smb://files.lab.test/share?password=private-password", "smb://files.lab.test/share#part", "smb://files.lab.test", "smb://files.lab.test/share/../other", "smb://files.lab.test/share/%2e%2e/other", "smb://files.lab.test:445/share", "smb://files.lab.test:/share", "nfs://storage.lab.test/exports//bot", "smb://files.lab.test/share/%00", "not-a-network-share"} {
		cases = append(cases, map[string]string{"STATE_NETWORK_URL": source})
	}
	for key, value := range map[string]string{"STORAGE_CLASS": "ocs-storagecluster-cephfs", "STATE_SMB_USERNAME": "user-without-password", "STATE_SMB_PASSWORD": "private-password", "STATE_SMB_DOMAIN": "DOMAIN", "STATE_SMB_SECRET": "../wrong", "STATE_SMB_GID": "0,nobrl"} {
		cases = append(cases, map[string]string{"STATE_NETWORK_URL": `\\files.lab.test\bot-state`, key: value})
	}
	cases = append(cases, map[string]string{"STATE_NETWORK_URL": "nfs://storage.lab.test/exports", "STATE_SMB_USERNAME": "private-password"}, map[string]string{"STATE_SMB_PASSWORD": "private-password"})
	cases = append(cases, map[string]string{"STATE_NETWORK_URL": "//files.lab.test/share", "STATE_SMB_GID": "4294967296"})
	for i, input := range cases {
		for _, part := range []string{"bootstrap", "deployment"} {
			env := shortEnv()
			for k, v := range input {
				env[k] = v
			}
			var out bytes.Buffer
			err := Render(&out, env, part)
			if err == nil || out.Len() != 0 {
				t.Fatalf("case %d: invalid storage accepted", i)
			}
			if strings.Contains(err.Error(), "private-password") {
				t.Fatal("credentials leaked in validation error")
			}
		}
	}
}

func TestDefaultStorageStillSupportsDynamicProvisioning(t *testing.T) {
	for _, class := range []string{"", "ocs-storagecluster-cephfs"} {
		env := shortEnv()
		env["STATE_NETWORK_URL"] = ""
		env["STORAGE_CLASS"] = class
		bootstrap := storageResources(t, env, "bootstrap")
		if bootstrap["PersistentVolume/cvebridge-security-bot-state"] != nil {
			t.Fatal("default storage unexpectedly created a static PV")
		}
		pvc := obj(storageResources(t, env, "deployment")["PersistentVolumeClaim/cvebridge-state"]["spec"])
		if pvc["volumeName"] != nil || obj(obj(pvc["resources"])["requests"])["storage"] != "1Gi" {
			t.Fatal("dynamic provisioning changed")
		}
		value, present := pvc["storageClassName"]
		if (class == "" && present) || (class != "" && value != class) {
			t.Fatal("cluster default or explicit storage class changed")
		}
	}
}

func TestStoreUsesRollbackJournalAndPreservesExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO cve_seen VALUES (?,?,?,?)`, channelID, "cluster-123", "CVE-2026-12345", timestamp()); err != nil {
		t.Fatal(err)
	}
	// A copied database may retain WAL mode. Reopening must switch back to a
	// rollback journal without losing the confirmed CVE state.
	if _, err := store.DB.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var mode string
	var sync, count int
	if err := store.DB.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "delete" {
		t.Fatal(mode, err)
	}
	if err := store.DB.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil || sync != 2 {
		t.Fatal(sync, err)
	}
	if err := store.DB.QueryRow(`SELECT COUNT(*) FROM cve_seen WHERE cve='CVE-2026-12345'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("confirmed CVE state lost", err)
	}
}
