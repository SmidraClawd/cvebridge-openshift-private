package bridge

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type stateStorage struct {
	PVC, PV, Secret M
}

// Network storage is mounted by the cluster, not opened as a URL by SQLite.
// A static claim must opt out of the cluster's default StorageClass and bind
// only to its own PV. The PV belongs in the administrator's bootstrap file.
func renderStateStorage(c Config) (stateStorage, error) {
	ns := c.Get("NAMESPACE", "cvebridge")
	size := c.Get("STATE_STORAGE_SIZE", "1Gi")
	pvc := M{"accessModes": []string{"ReadWriteOnce"}, "resources": M{"requests": M{"storage": size}}}
	storage := stateStorage{PVC: resource("PersistentVolumeClaim", "cvebridge-state", ns, M{"spec": pvc})}
	source := strings.TrimSpace(c.Get("STATE_NETWORK_URL", ""))
	smbKeys := []string{"STATE_SMB_USERNAME", "STATE_SMB_PASSWORD", "STATE_SMB_DOMAIN", "STATE_SMB_SECRET", "STATE_SMB_GID"}
	if source == "" {
		for _, key := range smbKeys {
			if c.Get(key, "") != "" {
				return storage, fmt.Errorf("%s requires an SMB STATE_NETWORK_URL", key)
			}
		}
		if class := c.Get("STORAGE_CLASS", ""); class != "" {
			pvc["storageClassName"] = class
		}
		return storage, nil
	}
	if c.Get("STORAGE_CLASS", "") != "" {
		return storage, fmt.Errorf("leave STORAGE_CLASS empty when using STATE_NETWORK_URL")
	}
	u, err := parseStateNetworkURL(source)
	if err != nil {
		return storage, err
	}
	name := "cvebridge-" + ns + "-state"
	pvc["storageClassName"] = ""
	pvc["volumeName"] = name
	pv := M{
		"capacity": M{"storage": size}, "accessModes": []string{"ReadWriteOnce"},
		"persistentVolumeReclaimPolicy": "Retain", "storageClassName": "",
		"claimRef": M{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "name": "cvebridge-state", "namespace": ns},
	}
	if u.Scheme == "nfs" {
		for _, key := range smbKeys {
			if c.Get(key, "") != "" {
				return storage, fmt.Errorf("%s is only used with SMB storage", key)
			}
		}
		pv["nfs"] = M{"server": u.Hostname(), "path": u.Path}
		pv["mountOptions"] = []string{"hard", "nosuid", "nodev", "noexec"}
	} else {
		secret := c.Get("STATE_SMB_SECRET", "cvebridge-storage")
		if !NS.MatchString(secret) || placeholder(secret) {
			return storage, fmt.Errorf("STATE_SMB_SECRET must be a valid Secret name")
		}
		username, password, domain := c.Get("STATE_SMB_USERNAME", ""), c.Get("STATE_SMB_PASSWORD", ""), c.Get("STATE_SMB_DOMAIN", "")
		if (username == "") != (password == "") || (domain != "" && username == "") {
			return storage, fmt.Errorf("fill both STATE_SMB_USERNAME and STATE_SMB_PASSWORD, or use an existing STATE_SMB_SECRET")
		}
		if username != "" {
			if placeholder(username) || placeholder(password) || placeholder(domain) {
				return storage, fmt.Errorf("replace placeholders in SMB credentials")
			}
			data := M{"username": username, "password": password}
			if domain != "" {
				data["domain"] = domain
			}
			storage.Secret = resource("Secret", secret, ns, M{"type": "Opaque", "stringData": data})
		}
		gid := c.Get("STATE_SMB_GID", "0")
		_, gidError := strconv.ParseUint(gid, 10, 32)
		if gidError != nil || !regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`).MatchString(gid) {
			return storage, fmt.Errorf("STATE_SMB_GID must be a numeric group ID")
		}
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		subDir := strings.Join(parts[1:], "/")
		attributes := M{"source": "//" + u.Host + "/" + parts[0]}
		if subDir != "" {
			attributes["subDir"] = subDir
		}
		pv["csi"] = M{
			"driver": "smb.csi.k8s.io", "volumeHandle": u.Host + "#" + subDir + "#" + parts[0],
			"volumeAttributes": attributes, "nodeStageSecretRef": M{"name": secret, "namespace": ns},
		}
		// Keep remote byte-range locks enabled. No nobrl, noperm or world-writable modes.
		pv["mountOptions"] = []string{"nosuid", "nodev", "noexec", "cache=strict", "noserverino", "dir_mode=0770", "file_mode=0660", "gid=" + gid}
	}
	storage.PV = resource("PersistentVolume", name, "", M{"spec": pv})
	return storage, nil
}

// Accept UNC, smb://host/share/folder, nfs://host/export and host:/export.
// Never echo the input in errors: pasted URLs might contain credentials.
func parseStateNetworkURL(source string) (*url.URL, error) {
	invalid := func() (*url.URL, error) {
		return nil, fmt.Errorf("STATE_NETWORK_URL must be \\\\server\\share, smb://server/share or nfs://server/export; no credentials, query or fragment")
	}
	if strings.HasPrefix(source, `\\`) {
		source = strings.ReplaceAll(source, `\`, "/")
	}
	if strings.HasPrefix(source, "//") {
		source = "smb:" + source
	} else if !strings.Contains(source, "://") {
		if server, export, ok := strings.Cut(source, ":/"); ok {
			source = "nfs://" + server + "/" + export
		}
	}
	u, err := url.Parse(source)
	if err != nil || (u.Scheme != "smb" && u.Scheme != "nfs") || u.Hostname() == "" || u.Port() != "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(source, "#") || placeholder(source) {
		return invalid()
	}
	host := u.Hostname()
	if u.Host != host && u.Host != "["+host+"]" {
		return invalid()
	}
	if net.ParseIP(host) == nil && !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9.])?$`).MatchString(host) {
		return invalid()
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasPrefix(u.Path, "/") || u.Path == "" {
		return invalid()
	}
	for _, part := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\#?") {
			return invalid()
		}
		for _, r := range part {
			if r < 32 || r == 127 {
				return invalid()
			}
		}
	}
	return u, nil
}
