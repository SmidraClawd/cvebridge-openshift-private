package bridge

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

func resource(kind, name, namespace string, spec M) M {
	meta := M{"name": name}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	r := M{"apiVersion": "v1", "kind": kind, "metadata": meta}
	for k, v := range spec {
		r[k] = v
	}
	return r
}
func rbac(kind, name, namespace string, spec M) M {
	r := resource(kind, name, namespace, spec)
	r["apiVersion"] = "rbac.authorization.k8s.io/v1"
	return r
}
func placeholder(v string) bool {
	return strings.Contains(v, "CHANGE_ME") || strings.Contains(v, "example.com") || strings.Contains(v, "REPLACE_")
}

// Render produces a Kubernetes List. JSON is valid YAML and is accepted by oc.
// Secrets are runtime resources; the image contains no company configuration.
func Render(w io.Writer, values map[string]string, part string) error {
	if part != "deployment" && part != "bootstrap" {
		return fmt.Errorf("part must be deployment or bootstrap")
	}
	c, e := NewConfig(values)
	if e != nil {
		return e
	}
	ns := c.Get("NAMESPACE", "")
	if !NS.MatchString(ns) || ns == "default" || ns == "kube-system" || strings.HasPrefix(ns, "openshift-") {
		return fmt.Errorf("choose a dedicated NAMESPACE")
	}
	image, e := deploymentImage(c)
	if e != nil {
		return e
	}
	webhook := c.Get("WEBHOOK_URL", "")
	u, e := url.Parse(webhook)
	if e != nil || u.Hostname() == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || placeholder(webhook) {
		return fmt.Errorf("WEBHOOK_URL must be the internal service URL or an HTTPS route origin")
	}
	serviceHost := "cvebridge-webhook." + ns + ".svc"
	internal := u.Hostname() == serviceHost || u.Hostname() == serviceHost+".cluster.local"
	if internal {
		if u.Scheme != "http" || u.Port() != "8001" {
			return fmt.Errorf("internal WEBHOOK_URL must use http and service port 8001")
		}
	} else if u.Scheme != "https" || u.Port() != "" || strings.HasSuffix(u.Hostname(), ".svc") || strings.HasSuffix(u.Hostname(), ".svc.cluster.local") {
		return fmt.Errorf("external WEBHOOK_URL must be an HTTPS origin without a port")
	}
	for _, k := range []string{"MATTERMOST_BOT_TOKEN", "MATTERMOST_COMMAND_TOKEN", "STACKROX_TOKEN", "STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN"} {
		if c.Get(k, "") == "" || placeholder(c.Get(k, "")) {
			return fmt.Errorf("fill %s in .env", k)
		}
	}
	if id := c.Get("MATTERMOST_BOT_USER_ID", ""); (id != "" && !ID.MatchString(id)) || len(c.Scopes) == 0 || len(c.Users) == 0 {
		return fmt.Errorf("configure approved channel scope and user mappings; optional bot ID must be valid")
	}
	if len(c.ScheduleScopes) > 0 && c.Get("STACKROX_SCHEDULE_TOKEN", "") == "" {
		return fmt.Errorf("STACKROX_SCHEDULE_TOKEN is required for scheduling")
	}
	if len(c.ScheduleScopes) > 0 && c.Get("SCHEDULE_SERVICE_USER", "") != "system:serviceaccount:"+ns+":cvebridge-reporter" {
		return fmt.Errorf("SCHEDULE_SERVICE_USER must match system:serviceaccount:%s:cvebridge-reporter", ns)
	}
	items := []any{}
	if part == "bootstrap" {
		items = append(items, resource("Namespace", ns, "", M{}), rbac("ClusterRole", "cvebridge-"+ns, "", M{"rules": []any{M{"apiGroups": []string{"authorization.k8s.io"}, "resources": []string{"subjectaccessreviews"}, "verbs": []string{"create"}}}}), rbac("ClusterRoleBinding", "cvebridge-"+ns, "", M{"roleRef": M{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cvebridge-" + ns}, "subjects": []any{M{"kind": "ServiceAccount", "name": "cvebridge", "namespace": ns}}}))
		approved := []string{}
		for _, scopes := range c.ScheduleScopes {
			approved = append(approved, scopes...)
		}
		for _, target := range unique(approved) {
			items = append(items, rbac("Role", "cvebridge-reporter-"+ns, target, M{"rules": []any{M{"apiGroups": []string{"apps"}, "resources": []string{"deployments"}, "verbs": []string{"list"}}}}), rbac("RoleBinding", "cvebridge-reporter-"+ns, target, M{"roleRef": M{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "cvebridge-reporter-" + ns}, "subjects": []any{M{"kind": "ServiceAccount", "name": "cvebridge-reporter", "namespace": ns}}}))
		}
	} else {
		env := map[string]string{}
		secrets := map[string]string{}
		keys := []string{"NAMESPACE", "MATTERMOST_INTERNAL_URL", "STACKROX_URL", "STACKROX_CLUSTER_ID", "MATTERMOST_BOT_USER_ID", "MATTERMOST_CHANNEL_SCOPES", "MATTERMOST_CHANNEL_POLICIES", "MATTERMOST_SCHEDULE_SCOPES", "MATTERMOST_SCHEDULE_MANAGERS", "MATTERMOST_KUBE_USER_MAP", "SCHEDULE_SERVICE_USER", "SCHEDULE_DEFAULT_TIMEZONE", "STACKROX_SCANNER_COMPONENT", "STACKROX_DELEGATE_SCAN", "DATABASE_MAX_AGE_HOURS", "CVE_ALERTS_ENABLED", "CVE_ALERT_MIN_CVSS", "CVE_ALERT_FIRST_REPORT"}
		for _, k := range keys {
			if v, ok := c.Env[k]; ok {
				env[k] = v
			}
		}
		for _, k := range []string{"MATTERMOST_BOT_TOKEN", "MATTERMOST_COMMAND_TOKEN", "MATTERMOST_ACS_COMMAND_TOKEN", "STACKROX_TOKEN", "STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"} {
			secrets[k] = values[k]
		}
		env["MATTERMOST_DIALOG_URL"] = webhook + "/slash/cve/dialog"
		env["STATE_FILE"] = "/data/requests.sqlite3"
		volumes := []any{M{"name": "data", "persistentVolumeClaim": M{"claimName": "cvebridge-state"}}}
		mounts := []any{M{"name": "data", "mountPath": "/data"}}
		caData := map[string]string{}
		for _, kind := range []string{"STACKROX", "MATTERMOST"} {
			path := values[kind+"_CA_FILE"]
			if path == "" {
				continue
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return fmt.Errorf("cannot read %s_CA_FILE", kind)
			}
			if _, e = client(path); e != nil {
				return e
			}
			remaining := b
			for {
				block, rest := pem.Decode(remaining)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					return fmt.Errorf("%s_CA_FILE must contain only public CA certificates", kind)
				}
				remaining = rest
			}
			name := strings.ToLower(kind) + ".pem"
			caData[name] = string(b)
			env[kind+"_CA_FILE"] = "/ca/" + name
		}
		if len(caData) > 0 {
			items = append(items, resource("ConfigMap", "cvebridge-ca", ns, M{"data": caData}))
			volumes = append(volumes, M{"name": "ca", "configMap": M{"name": "cvebridge-ca"}})
			mounts = append(mounts, M{"name": "ca", "mountPath": "/ca", "readOnly": true})
		}
		items = append(items, resource("ServiceAccount", "cvebridge", ns, M{}), resource("ServiceAccount", "cvebridge-reporter", ns, M{"automountServiceAccountToken": false}), resource("Secret", "cvebridge-integration", ns, M{"type": "Opaque", "stringData": secrets}), resource("ConfigMap", "cvebridge-config", ns, M{"data": env}))
		pvcSpec := M{"accessModes": []string{"ReadWriteOnce"}, "resources": M{"requests": M{"storage": c.Get("STATE_STORAGE_SIZE", "1Gi")}}}
		if v := c.Get("STORAGE_CLASS", ""); v != "" {
			pvcSpec["storageClassName"] = v
		}
		items = append(items, resource("PersistentVolumeClaim", "cvebridge-state", ns, M{"spec": pvcSpec}))
		labels := M{"app.kubernetes.io/name": "cvebridge"}
		pullPolicy := "IfNotPresent"
		if strings.HasSuffix(image, ":latest") {
			pullPolicy = "Always"
		}
		container := M{"name": "bot", "image": image, "imagePullPolicy": pullPolicy, "ports": []any{M{"name": "webhook", "containerPort": 8001}}, "envFrom": []any{M{"configMapRef": M{"name": "cvebridge-config"}}, M{"secretRef": M{"name": "cvebridge-integration"}}}, "volumeMounts": mounts, "securityContext": M{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": M{"drop": []string{"ALL"}}}, "resources": M{"requests": M{"cpu": "100m", "memory": "128Mi"}, "limits": M{"cpu": "1", "memory": "512Mi"}}}
		for _, probe := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
			container[probe] = M{"httpGet": M{"path": "/healthz", "port": "webhook"}, "periodSeconds": 10, "failureThreshold": 6}
		}
		pod := M{"serviceAccountName": "cvebridge", "terminationGracePeriodSeconds": 30, "securityContext": M{"runAsNonRoot": true, "seccompProfile": M{"type": "RuntimeDefault"}}, "containers": []any{container}, "volumes": volumes}
		if secret := c.Get("IMAGE_PULL_SECRET", ""); secret != "" {
			if !NS.MatchString(secret) {
				return fmt.Errorf("invalid IMAGE_PULL_SECRET")
			}
			pod["imagePullSecrets"] = []any{M{"name": secret}}
		}
		deployment := resource("Deployment", "cvebridge", ns, M{"spec": M{"replicas": 1, "strategy": M{"type": "Recreate"}, "selector": M{"matchLabels": labels}, "template": M{"metadata": M{"labels": labels}, "spec": pod}}})
		deployment["apiVersion"] = "apps/v1"
		items = append(items, deployment, resource("Service", "cvebridge-webhook", ns, M{"spec": M{"selector": labels, "ports": []any{M{"name": "webhook", "port": 8001, "targetPort": "webhook"}}}}))
		if !internal {
			route := resource("Route", "cvebridge-webhook", ns, M{"spec": M{"host": u.Hostname(), "path": "/slash/cve", "to": M{"kind": "Service", "name": "cvebridge-webhook"}, "port": M{"targetPort": "webhook"}, "tls": M{"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}}})
			route["apiVersion"] = "route.openshift.io/v1"
			items = append(items, route)
		}
	}
	// Stable ordering of object contents is provided by encoding/json.
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(M{"apiVersion": "v1", "kind": "List", "items": items})
}
