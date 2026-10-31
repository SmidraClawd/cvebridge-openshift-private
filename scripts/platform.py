#!/usr/bin/env python3
"""Repeatable local installation. Never changes the user's default kubeconfig.

Only the dedicated k3d cluster 'cvebridge' is managed. Secret values are written
with mode 0600 under .local/ and are never passed as command-line arguments.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import quote
import ssl

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
VERSIONS = json.loads((ROOT / "config/versions.json").read_text())
KUBECONFIG = LOCAL / "kubeconfig"
CLUSTER = "cvebridge"
NS = "cvebridge"
DEFAULT_NAMESPACE = object()


def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=2)
    path.chmod(0o600)


def run(args, *, capture=False, input=None, timeout=1200, env=None):
    result = subprocess.run([str(a) for a in args], cwd=ROOT, input=input, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            timeout=timeout, env=env)
    if result.returncode:
        if capture:
            # Callers only use capture for commands that do not echo secret inputs.
            print(result.stderr[-2000:], file=sys.stderr)
        raise RuntimeError(f"Command failed: {args[0]} (exit {result.returncode})")
    return result.stdout if capture else None


def privileged():
    result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        return []
    result = subprocess.run(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        return ["sudo", "-n"]
    raise RuntimeError("Docker is not accessible. Start Docker and arrange Docker access, then rerun this command.")


def kube(*args, capture=False, payload=None):
    return run(["kubectl", "--kubeconfig", KUBECONFIG, "--request-timeout=60s", *args],
               capture=capture, input=json.dumps(payload) if payload is not None else None)


def apply(resources):
    kube("apply", "-f", "-", payload={"apiVersion": "v1", "kind": "List", "items": resources})


def obj(kind, name, spec=None, namespace=DEFAULT_NAMESPACE, api="v1", **extra):
    if namespace is DEFAULT_NAMESPACE:
        namespace = NS
    item = {"apiVersion": api, "kind": kind, "metadata": {"name": name, "labels": {"app.kubernetes.io/part-of": "cvebridge"}}}
    if namespace:
        item["metadata"]["namespace"] = namespace
    if spec is not None:
        item["spec"] = spec
    item.update(extra)
    return item


def secret(name, data, namespace=DEFAULT_NAMESPACE):
    return obj("Secret", name, namespace=namespace, type="Opaque", stringData=data)


def pvc(name, size="1Gi", namespace=DEFAULT_NAMESPACE):
    return obj("PersistentVolumeClaim", name, {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": size}}}, namespace=namespace)


def service(name, port, target=None, node_port=None):
    spec = {"selector": {"app": name}, "ports": [{"port": port, "targetPort": target or port}]}
    if node_port:
        spec["type"] = "NodePort"
        spec["ports"][0]["nodePort"] = node_port
    return obj("Service", name, spec)


def resources(memory="128Mi", limit="512Mi", cpu="100m"):
    return {"requests": {"cpu": cpu, "memory": memory}, "limits": {"memory": limit}}


def deployment(name, containers, volumes=None, service_account=None, secure=True):
    spec = {"containers": containers, "automountServiceAccountToken": bool(service_account)}
    if volumes:
        spec["volumes"] = volumes
    if service_account:
        spec["serviceAccountName"] = service_account
    if secure:
        spec["securityContext"] = {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    return obj("Deployment", name, {"replicas": 1, "strategy": {"type": "Recreate"},
                                      "selector": {"matchLabels": {"app": name}},
                                      "template": {"metadata": {"labels": {"app": name}}, "spec": spec}}, api="apps/v1")


def envs(values):
    return [{"name": k, "value": str(v)} for k, v in values.items()]


def local_settings():
    return {"namespace": NS, "app_image": VERSIONS["app"], "public_url": "http://localhost:18080",
            "mattermost_public_url": "http://localhost:18065", "mattermost_internal_url": "http://mattermost.cvebridge.svc:8065",
            "stackrox_url": "https://central.stackrox.svc:443", "stackrox_cluster_id": "",
            "identity_header": "X-Forwarded-Email", "identity_prefix": "",
            "mattermost_channel_scopes": {},
            "mattermost_channel_policies": {}, "database_max_age_hours": 24,
            "mattermost_schedule_scopes": {}, "mattermost_schedule_managers": {},
            "cve_alerts_enabled": True, "cve_alert_min_cvss": 9, "cve_alert_first_report": False,
            "oidc_issuer": "http://localhost:15556/dex", "oidc_client_id": "cvebridge",
            "skip_discovery": True, "cookie_secure": False, "node_port": 30880,
            "login_url": "http://localhost:15556/dex/auth", "redeem_url": "http://dex.cvebridge.svc:5556/dex/token",
            "jwks_url": "http://dex.cvebridge.svc:5556/dex/keys", "profile_url": "http://dex.cvebridge.svc:5556/dex/userinfo"}


def common_manifests(settings):
    global NS
    NS = settings["namespace"]
    provider = settings.get("auth_provider", "oidc")
    if provider not in {"oidc", "openshift"}:
        raise RuntimeError("auth_provider must be oidc or openshift")
    if provider == "openshift" and (not settings.get("openshift_proxy_image")
                                    or "REPLACE" in settings["openshift_proxy_image"]):
        raise RuntimeError("Set openshift_proxy_image to the OAuth proxy image approved for your cluster")
    env = {"AUTH_PROVIDER": provider, "PUBLIC_URL": settings["public_url"], "MATTERMOST_PUBLIC_URL": settings["mattermost_public_url"],
           "MATTERMOST_INTERNAL_URL": settings["mattermost_internal_url"], "STACKROX_URL": settings["stackrox_url"],
           "STACKROX_CLUSTER_ID": settings["stackrox_cluster_id"], "STACKROX_CA_FILE": "/rox-ca/ca.pem",
           "MATTERMOST_CHANNEL_SCOPES": json.dumps(settings.get("mattermost_channel_scopes", {})),
           "MATTERMOST_CHANNEL_POLICIES": json.dumps(settings.get("mattermost_channel_policies", {})),
           "MATTERMOST_SCHEDULE_SCOPES": json.dumps(settings.get("mattermost_schedule_scopes", {})),
           "MATTERMOST_SCHEDULE_MANAGERS": json.dumps(settings.get("mattermost_schedule_managers", {})),
           "SCHEDULE_SERVICE_USER": "system:serviceaccount:"+settings["namespace"]+":acs-reporter",
           "SCHEDULE_DEFAULT_TIMEZONE": settings.get("schedule_default_timezone", "Europe/Stockholm"),
           "MATTERMOST_DIALOG_URL": (settings.get("webhook_public_url") or
               "http://cvebridge-webhook."+NS+".svc:8001").rstrip("/")+"/slash/cve/dialog",
           "DATABASE_MAX_AGE_HOURS": str(settings.get("database_max_age_hours", 24)),
           "CVE_ALERTS_ENABLED": str(settings.get("cve_alerts_enabled", True)).lower(),
           "CVE_ALERT_MIN_CVSS": str(settings.get("cve_alert_min_cvss", 9)),
           "CVE_ALERT_FIRST_REPORT": str(settings.get("cve_alert_first_report", False)).lower(),
           "STACKROX_SCANNER_COMPONENT": settings.get("stackrox_scanner_component", "SCANNER"),
           "STACKROX_DELEGATE_SCAN": str(settings.get("stackrox_delegate_scan", False)).lower(),
           "IDENTITY_HEADER": settings.get("identity_header", "X-Forwarded-Email"), "IDENTITY_PREFIX": settings.get("identity_prefix", "")}
    locked = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
              "capabilities": {"drop": ["ALL"]}}
    app = {"name": "app", "image": settings["app_image"], "imagePullPolicy": "IfNotPresent",
           "env": envs(env), "envFrom": [{"secretRef": {"name": "cvebridge-integration"}}],
           "securityContext": locked, "resources": resources("64Mi", "256Mi", "50m"),
           "ports": [{"name": "webhook", "containerPort": 8001}],
           "volumeMounts": [{"name": "state", "mountPath": "/data"}, {"name": "rox-ca", "mountPath": "/rox-ca", "readOnly": True}],
           "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8001}, "initialDelaySeconds": 2}}
    proxy_args = []
    if provider == "oidc":
        proxy_args = ["--provider=oidc", "--http-address=0.0.0.0:4180", "--upstream=http://127.0.0.1:8000/",
                  "--oidc-issuer-url=" + settings["oidc_issuer"], "--client-id=" + settings["oidc_client_id"],
                  "--redirect-url=" + settings["public_url"] + "/oauth2/callback", "--email-domain=*",
                  "--cookie-secure=" + str(settings.get("cookie_secure", True)).lower(),
                  "--cookie-samesite=lax", "--cookie-name=_cvebridge", "--cookie-expire=8h",
                  "--pass-user-headers=true", "--pass-basic-auth=false", "--skip-provider-button=true",
                  "--approval-prompt=" + settings.get("approval_prompt", "auto"),
                  "--scope=openid email profile groups", "--code-challenge-method=S256",
                  "--request-logging=false", "--standard-logging=true", "--auth-logging=false"]
    if provider == "oidc" and settings.get("skip_discovery"):
        proxy_args += ["--skip-oidc-discovery=true", "--login-url=" + settings["login_url"],
                       "--redeem-url=" + settings["redeem_url"], "--oidc-jwks-url=" + settings["jwks_url"],
                       "--profile-url=" + settings["profile_url"]]
    proxy = {"name": "proxy", "image": VERSIONS["proxy"], "args": proxy_args,
             "envFrom": [{"secretRef": {"name": "cvebridge-proxy"}}], "securityContext": locked,
             "resources": resources("32Mi", "128Mi", "25m"), "ports": [{"name": "browser", "containerPort": 4180}],
             "readinessProbe": {"httpGet": {"path": "/ping", "port": 4180}, "initialDelaySeconds": 2}}
    if provider == "openshift":
        proxy["image"] = settings["openshift_proxy_image"]
        proxy["args"] = ["--provider=openshift", "--http-address=0.0.0.0:4180", "--https-address=",
                         "--upstream=http://127.0.0.1:8000/", "--proxy-prefix=/oauth2",
                         "--client-id="+settings.get("openshift_oauth_client_id", "cvebridge-"+NS),
                         "--client-secret-file=/proxy-secrets/OAUTH2_PROXY_CLIENT_SECRET",
                         "--cookie-secret-file=/proxy-secrets/OAUTH2_PROXY_COOKIE_SECRET",
                         "--redirect-url="+settings["public_url"]+"/oauth2/callback",
                         "--scope=user:info", "--cookie-secure=true", "--cookie-samesite=lax",
                         "--cookie-name=_cvebridge", "--cookie-expire=8h", "--pass-basic-auth=false",
                         "--pass-user-headers=true", "--pass-access-token=true",
                         "--request-logging=false", "--skip-provider-button=true"]
        proxy.pop("envFrom")
        proxy["volumeMounts"] = [{"name":"proxy-secrets", "mountPath":"/proxy-secrets", "readOnly":True}]
        proxy["readinessProbe"]["httpGet"]["path"] = "/oauth2/healthz"
    app_deploy = deployment("cvebridge", [app, proxy],
                            [{"name": "state", "persistentVolumeClaim": {"claimName": "cvebridge-state"}},
                             {"name": "rox-ca", "secret": {"secretName": "cvebridge-rox-ca"}}], "cvebridge")
    app_deploy["spec"]["template"]["spec"]["securityContext"]["fsGroup"] = 10001 if settings.get("node_port") else None
    if provider == "openshift":
        app_deploy["spec"]["template"]["spec"]["volumes"].append(
            {"name":"proxy-secrets", "secret":{"secretName":"cvebridge-proxy"}})
    if settings.get("mattermost_custom_ca"):
        app["env"].append({"name":"MATTERMOST_CA_FILE", "value":"/mattermost-ca/ca.pem"})
        app["volumeMounts"].append({"name":"mattermost-ca", "mountPath":"/mattermost-ca", "readOnly":True})
        app_deploy["spec"]["template"]["spec"]["volumes"].append(
            {"name":"mattermost-ca", "secret":{"secretName":"cvebridge-mattermost-ca"}})
    if not settings.get("node_port"):
        del app_deploy["spec"]["template"]["spec"]["securityContext"]["fsGroup"]
    items = [obj("Namespace", NS, namespace=None), obj("ServiceAccount", "cvebridge"),
             obj("ClusterRole", NS + "-reviewer", namespace=None, api="rbac.authorization.k8s.io/v1", rules=[
                 {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["list"]},
                 {"apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"]}]),
             obj("ClusterRoleBinding", NS + "-reviewer", namespace=None, api="rbac.authorization.k8s.io/v1",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": NS+"-reviewer"},
                 subjects=[{"kind": "ServiceAccount", "name": "cvebridge", "namespace": NS}]),
             pvc("cvebridge-state", "128Mi"), app_deploy,
             obj("Service", "cvebridge", {"selector": {"app": "cvebridge"}, "type": "NodePort" if settings.get("node_port") else "ClusterIP",
                 "ports": [{"name": "browser", "port": 4180, "targetPort": 4180, **({"nodePort": settings["node_port"]} if settings.get("node_port") else {})}]}),
             obj("Service", "cvebridge-webhook", {"selector": {"app": "cvebridge"}, "ports": [{"name":"webhook", "port": 8001, "targetPort": 8001}]})]
    if provider == "openshift":
        reviewer = next(item for item in items if item["kind"] == "ClusterRole")
        reviewer["rules"].append({"apiGroups":["authentication.k8s.io"], "resources":["tokenreviews"], "verbs":["create"]})
        items += [
            obj("Role", NS+"-oauth-ca-reader", namespace="openshift-config-managed", api="rbac.authorization.k8s.io/v1",
                rules=[{"apiGroups":[""], "resources":["configmaps"], "resourceNames":["oauth-serving-cert"], "verbs":["get","list","watch"]}]),
            obj("RoleBinding", NS+"-oauth-ca-reader", namespace="openshift-config-managed", api="rbac.authorization.k8s.io/v1",
                roleRef={"apiGroup":"rbac.authorization.k8s.io", "kind":"Role", "name":NS+"-oauth-ca-reader"},
                subjects=[{"kind":"ServiceAccount", "name":"cvebridge", "namespace":NS}])]
    # The browser backend has no Service or externally reachable socket. Only
    # the proxy in the SAME pod can connect to its loopback listener.
    if settings.get("mattermost_schedule_scopes"):
        items.append(obj("ServiceAccount", "acs-reporter", automountServiceAccountToken=False))
        for namespace in sorted({n for scope in settings["mattermost_schedule_scopes"].values() for n in scope}):
            items.append(obj("Role", NS+"-scheduled-reader", namespace=namespace, api="rbac.authorization.k8s.io/v1",
                             rules=[{"apiGroups":["apps"],"resources":["deployments"],"verbs":["list"]}]))
            items.append(obj("RoleBinding", NS+"-scheduled-reader", namespace=namespace, api="rbac.authorization.k8s.io/v1",
                             roleRef={"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":NS+"-scheduled-reader"},
                             subjects=[{"kind":"ServiceAccount","name":"acs-reporter","namespace":NS}]))
    if not settings.get("node_port"):
        host = settings["public_url"].split("://", 1)[1].split("/")[0]
        items.append(obj("Route", "cvebridge", {"host": host, "to": {"kind": "Service", "name": "cvebridge"},
                        "port": {"targetPort": "browser"}, "tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}}, api="route.openshift.io/v1"))
        if settings.get("webhook_public_url"):
            hook_host = settings["webhook_public_url"].split("://",1)[1].split("/")[0]
            items.append(obj("Route", "cvebridge-webhook", {
                "host":hook_host, "path":"/slash/cve", "to":{"kind":"Service", "name":"cvebridge-webhook"},
                "port":{"targetPort":"webhook"}, "tls":{"termination":"edge", "insecureEdgeTerminationPolicy":"Redirect"}},
                api="route.openshift.io/v1"))
    return items


def demo_manifests(creds):
    import bcrypt
    passwords = [{"email": user+"@demo.local", "hash": bcrypt.hashpw(creds[user].encode(), bcrypt.gensalt()).decode(),
                  "username": user, "userID": user+"-demo-id", "emailVerified": True} for user in ["alice", "bob"]]
    dex_config = {"issuer": "http://localhost:15556/dex", "storage": {"type": "sqlite3", "config": {"file": "/data/dex.db"}},
                  "web": {"http": "0.0.0.0:5556"}, "oauth2": {"skipApprovalScreen": True},
                  "enablePasswordDB": True, "staticPasswords": passwords,
                  "staticClients": [{"id": "cvebridge", "name": "CVE Bridge", "secret": creds["oidc_client_secret"],
                                     "redirectURIs": ["http://localhost:18080/oauth2/callback"]}]}
    dex = deployment("dex", [{"name": "dex", "image": VERSIONS["dex"], "args": ["dex", "serve", "/config/config.json"],
                      "resources": resources("64Mi", "192Mi", "50m"), "securityContext": {"runAsUser": 10001, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                      "ports": [{"containerPort": 5556}], "volumeMounts": [{"name": "config", "mountPath": "/config", "readOnly": True}, {"name": "data", "mountPath": "/data"}]}],
                     [{"name": "config", "secret": {"secretName": "dex-config"}}, {"name": "data", "persistentVolumeClaim": {"claimName": "dex-data"}}])
    dex["spec"]["template"]["spec"]["securityContext"]["fsGroup"] = 10001
    postgres = deployment("postgres", [{"name": "postgres", "image": VERSIONS["postgres"],
                          "envFrom": [{"secretRef": {"name": "postgres-config"}}], "resources": resources("96Mi", "384Mi", "100m"),
                          "ports": [{"containerPort": 5432}], "volumeMounts": [{"name": "data", "mountPath": "/var/lib/postgresql/data"}],
                          "readinessProbe": {"exec": {"command": ["pg_isready", "-U", "mattermost"]}, "initialDelaySeconds": 5}}],
                         [{"name": "data", "persistentVolumeClaim": {"claimName": "postgres-data"}}], secure=False)
    mm_env = {"MM_SERVICESETTINGS_SITEURL": "http://localhost:18065", "MM_SQLSETTINGS_DRIVERNAME": "postgres",
              "MM_SERVICESETTINGS_ENABLELOCALMODE": "true", "MM_SERVICESETTINGS_ENABLECOMMANDS": "true",
              "MM_SERVICESETTINGS_ENABLEDEVELOPER": "false", "MM_SERVICESETTINGS_ALLOWEDUNTRUSTEDINTERNALCONNECTIONS": "cvebridge-webhook.cvebridge.svc,cvebridge-webhook.cvebridge.svc.cluster.local",
              "MM_EMAILSETTINGS_SENDEMAILNOTIFICATIONS": "false", "MM_EMAILSETTINGS_REQUIREEMAILVERIFICATION": "false",
              "MM_TEAMSETTINGS_ENABLEOPENSERVER": "false", "MM_LOGSETTINGS_ENABLEFILE": "false",
              "MM_LOGSETTINGS_CONSOLELEVEL": "ERROR", "MM_SERVICESETTINGS_ENABLEBOTACCOUNTCREATION": "true",
              "MM_SERVICESETTINGS_ENABLEUSERACCESSTOKENS": "true", "MM_DIAGNOSTICSETTINGS_ENABLEDIAGNOSTICS": "false",
              "MM_SERVICESETTINGS_ENABLEPOSTUSERNAMEOVERRIDE": "true", "MM_SERVICESETTINGS_ENABLEPOSTICONOVERRIDE": "true",
              "MM_PLUGINSETTINGS_ENABLE": "false", "MM_PLUGINSETTINGS_ENABLEUPLOADS": "false",
              "MM_BLEVESETTINGS_ENABLEINDEXING": "false", "MM_BLEVESETTINGS_ENABLESEARCHING": "false"}
    mounts = [{"name": "data", "mountPath": "/mattermost/"+path, "subPath": path} for path in ["config", "data", "logs", "plugins", "client/plugins", "bleve-indexes"]]
    mm = deployment("mattermost", [{"name": "mattermost", "image": VERSIONS["mattermost"], "env": envs(mm_env),
                     "envFrom": [{"secretRef": {"name": "mattermost-db"}}], "securityContext": {"runAsUser": 2000},
                     "resources": resources("256Mi", "768Mi", "150m"), "ports": [{"containerPort": 8065}], "volumeMounts": mounts,
                     "readinessProbe": {"httpGet": {"path": "/api/v4/system/ping", "port": 8065}, "initialDelaySeconds": 15, "periodSeconds": 10}}],
                    [{"name": "data", "persistentVolumeClaim": {"claimName": "mattermost-data"}}])
    mm["spec"]["template"]["spec"]["securityContext"]["fsGroup"] = 2000
    items = [secret("dex-config", {"config.json": json.dumps(dex_config)}), pvc("dex-data", "128Mi"), dex, service("dex", 5556, node_port=30556),
             secret("postgres-config", {"POSTGRES_USER": "mattermost", "POSTGRES_DB": "mattermost", "POSTGRES_PASSWORD": creds["postgres"], "PGDATA": "/var/lib/postgresql/data/pgdata"}),
             pvc("postgres-data", "1Gi"), postgres, service("postgres", 5432),
             secret("mattermost-db", {"MM_SQLSETTINGS_DATASOURCE": "postgres://mattermost:"+creds["postgres"]+"@postgres.cvebridge.svc:5432/mattermost?sslmode=disable&connect_timeout=10"}),
             pvc("mattermost-data", "1Gi"), mm, service("mattermost", 8065, node_port=30665)]
    for users, namespace in [(["alice"], "demo-team-a"), (["bob"], "demo-team-b"), (["alice", "bob"], "demo-shared")]:
        items.append(obj("Namespace", namespace, namespace=None))
        items.append(obj("Role", "cve-reader", namespace=namespace, api="rbac.authorization.k8s.io/v1",
                         rules=[{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list"]}]))
        items.append(obj("RoleBinding", "cve-reader", namespace=namespace, api="rbac.authorization.k8s.io/v1",
                         roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "cve-reader"},
                         subjects=[{"kind": "User", "name": user+"@demo.local", "apiGroup": "rbac.authorization.k8s.io"} for user in users]))
        sample = deployment("sample-app", [{"name": "sample", "image": VERSIONS["sample"],
                         "command": ["python", "-c", "import time; time.sleep(10**8)"],
                         "securityContext": {"runAsUser": 10001, "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                         "resources": resources("16Mi", "64Mi", "10m")}])
        sample["metadata"]["namespace"] = namespace
        items.append(sample)
        items.append(obj("NetworkPolicy", "isolate-samples", {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}, namespace=namespace, api="networking.k8s.io/v1"))
    return items+java_demo_manifests()


def java_demo_manifests():
    """A real Java/JAR scan target, isolated with no Service and loopback HTTP."""
    sample = deployment("java-sample", [{"name":"java", "image":VERSIONS["java_sample"], "imagePullPolicy":"IfNotPresent",
        "command":["java", "-Xmx96m", "-XX:MaxMetaspaceSize=96m", "-Dlog4j2.formatMsgNoLookups=true", "-Djava.io.tmpdir=/tmp",
                   "-jar", "/app/spring-boot-application.jar", "--server.address=127.0.0.1"],
        "securityContext":{"runAsUser":10001,"readOnlyRootFilesystem":True,"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}},
        "resources":resources("96Mi","256Mi","50m"), "volumeMounts":[{"name":"tmp","mountPath":"/tmp"}]}],
        [{"name":"tmp","emptyDir":{"sizeLimit":"64Mi"}}])
    sample["metadata"]["namespace"] = "demo-team-a"
    sample["spec"]["template"]["spec"]["automountServiceAccountToken"] = False
    return [sample]


def credentials():
    f = LOCAL / "credentials.json"
    if f.exists():
        return json.loads(f.read_text())
    creds = {key: secrets.token_urlsafe(24) for key in ["admin", "alice", "bob", "integration", "postgres", "stackrox", "oidc_client_secret"]}
    creds["cookie_secret"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    private_json(f, creds)
    return creds


def cluster(prefix):
    clusters = json.loads(run(prefix+["k3d", "cluster", "list", "-o", "json"], capture=True))
    if not any(c["name"] == CLUSTER for c in clusters):
        args = prefix+["k3d", "cluster", "create", CLUSTER, "--image", VERSIONS["k3s"], "--servers", "1", "--agents", "0",
                       "--kubeconfig-update-default=false", "--kubeconfig-switch-context=false", "--servers-memory", "8g", "--api-port", "127.0.0.1:16550"]
        for host, node in [(18080, 30880), (18065, 30665), (15556, 30556), (18443, 30443)]:
            args += ["--port", f"127.0.0.1:{host}:{node}@server:0"]
        args += ["--k3s-arg", "--disable=traefik,servicelb,metrics-server@server:0", "--k3s-arg",
                 "--kubelet-arg=eviction-hard=memory.available<256Mi,nodefs.available<2Gi,imagefs.available<2Gi,nodefs.inodesFree<2%,imagefs.inodesFree<2%@server:0", "--wait", "--timeout", "180s"]
        run(args)
    data = run(prefix+["k3d", "kubeconfig", "get", CLUSTER], capture=True)
    fd = os.open(KUBECONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    KUBECONFIG.chmod(0o600)


def api(base, path, payload=None, token=None, context=None, method=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(base+path, data=None if payload is None else json.dumps(payload).encode(), headers=headers, method=method)
    try:
        with urlopen(request, timeout=60, context=context) as response:
            result = response.read()
            return (json.loads(result) if result else {}), response.headers
    except HTTPError as exc:
        # Print only status and upstream error ID; login credentials stay private.
        body = json.loads(exc.read() or b"{}")
        raise RuntimeError(f"API {path.split('?')[0]} failed: {exc.code} {body.get('id', '')}") from None


def bootstrap_mattermost(creds):
    base = "http://localhost:18065"
    state_path = LOCAL / "mattermost.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    if not state:
        admin, _ = api(base, "/api/v4/users", {"email": "admin@demo.local", "username": "labadmin", "password": creds["admin"]})
        state["admin_id"] = admin["id"]
        private_json(state_path, state)
    _, headers = api(base, "/api/v4/users/login", {"login_id": "labadmin", "password": creds["admin"]})
    admin_token = headers["Token"]
    if "team_id" not in state:
        team, _ = api(base, "/api/v4/teams", {"name": "devsecops", "display_name": "DevSecOps Lab", "type": "O"}, token=admin_token)
        state["team_id"] = team["id"]
        private_json(state_path, state)
    if "users" not in state:
        state["users"] = {}
    for user in ["alice", "bob"]:
        if user not in state["users"]:
            record, _ = api(base, "/api/v4/users", {"email": user+"@demo.local", "username": user, "password": creds[user]}, token=admin_token)
            state["users"][user] = record["id"]
            private_json(state_path, state)
        try:
            api(base, "/api/v4/teams/"+state["team_id"]+"/members", {"team_id": state["team_id"], "user_id": state["users"][user]}, token=admin_token)
        except RuntimeError as exc:
            if "400" not in str(exc):
                raise
    if "bot_user_id" not in state:
        bot, _ = api(base, "/api/v4/bots", {"username": "acs", "display_name": "ACS",
                        "description": "ACS hjälper utvecklingsteam att hitta StackRox-fynd i godkända namespaces."}, token=admin_token)
        state["bot_user_id"] = bot["user_id"]
        private_json(state_path, state)
    if "bot_access_token" not in state:
        token_record, _ = api(base, "/api/v4/users/"+state["bot_user_id"]+"/tokens",
                              {"description": "ACS local integration"}, token=admin_token)
        state["bot_access_token"], state["bot_token_id"] = token_record["token"], token_record["id"]
        private_json(state_path, state)
    state["integration_token"] = state["bot_access_token"]
    api(base, "/api/v4/teams/"+state["team_id"]+"/members",
        {"team_id": state["team_id"], "user_id": state["bot_user_id"]}, token=admin_token)
    avatar = ROOT/"assets/acs-avatar.png"
    if avatar.exists():
        import requests
        with avatar.open("rb") as image:
            response = requests.post(base+"/api/v4/users/"+state["bot_user_id"]+"/image",
                                     headers={"Authorization": "Bearer "+admin_token}, files={"image": (avatar.name, image, "image/png")}, timeout=30)
        if response.status_code not in [200, 201]:
            raise RuntimeError("ACS bot avatar could not be configured: "+str(response.status_code))
    # The bot owns new demo channels, avoiding implicit admin audience access.
    if "shared_channel_id" not in state:
        channel, _ = api(base, "/api/v4/channels", {"team_id": state["team_id"], "name": "team-security",
                           "display_name": "Team Security", "type": "P",
                           "purpose": "ACS: /cve status · /cve scan · /cve CVE-… . Beställarens godkända fynd delas med kanalens medlemmar."}, token=state["integration_token"])
        state["shared_channel_id"] = channel["id"]
        private_json(state_path, state)
    api(base, "/api/v4/channels/"+state["shared_channel_id"]+"/patch", {
        "purpose": "ACS: /cve status · /cve scan · /cve CVE-… . Beställarens godkända fynd delas med kanalens medlemmar.",
        "header": "ACS · /cve status | /cve scan | /cve CVE-YYYY-NNNN · Fynd delas i denna godkända teamkanal."},
        token=admin_token, method="PUT")
    for user_id in [state["bot_user_id"], state["users"]["alice"], state["users"]["bob"]]:
        api(base, "/api/v4/channels/"+state["shared_channel_id"]+"/members",
            {"user_id": user_id}, token=admin_token)
    # Upgrade only our previous service account out of the private audience.
    if state["users"].get("integration"):
        member_path = "/api/v4/channels/"+state["shared_channel_id"]+"/members/"+state["users"]["integration"]
        try:
            api(base, member_path, token=admin_token)
        except RuntimeError as exc:
            if "404" not in str(exc):
                raise
        else:
            api(base, member_path, token=admin_token, method="DELETE")
    # Bootstrap accounts are controlled by the installer. Mark their emails
    # verified administratively; the app rejects unverified account mappings.
    kube("-n", NS, "exec", "deploy/mattermost", "--", "/mattermost/bin/mmctl", "--local", "user", "verify", "alice", "bob", "labadmin")
    for key, trigger in [("command", "cve"), ("acs_command", "acs")]:
        command = {"team_id": state["team_id"], "trigger": trigger, "method": "P", "username": "ACS",
                   "icon_url": base+"/api/v4/users/"+state["bot_user_id"]+"/image",
                   "url": "http://cvebridge-webhook.cvebridge.svc:8001/slash/cve", "display_name": "ACS",
                   "description": "ACS — CVE-fynd från StackRox för teamets godkända namespaces", "auto_complete": True,
                   "auto_complete_desc": "Databasstatus, imageskanning, schema eller CVE-sökning", "auto_complete_hint": "status | scan [namespace] | schedule | CVE-YYYY-NNNN [namespace] | help"}
        if key in state:
            command = state[key] | command
            updated, _ = api(base, "/api/v4/commands/"+command["id"], command, token=admin_token, method="PUT")
            state[key] = command | updated
        else:
            state[key], _ = api(base, "/api/v4/commands", command, token=admin_token)
    private_json(state_path, state)
    return state


def integration_secret(mm, rox, identity_map=None):
    identity_path = LOCAL/"identity-map.json"
    mappings = json.loads(identity_path.read_text()) if identity_path.exists() else {}
    mappings.update({mm["users"][user]: user+"@demo.local" for user in ["alice", "bob"]})
    if identity_map:
        mappings.update(identity_map)
    private_json(identity_path, mappings)
    return secret("cvebridge-integration", {"STACKROX_TOKEN": rox["token"],
                   "STACKROX_SCAN_TOKEN": rox.get("scan_token", ""), "STACKROX_STATUS_TOKEN": rox.get("status_token", ""),
                   "STACKROX_SCHEDULE_TOKEN": rox.get("schedule_token", ""),
                   "MATTERMOST_TOKEN": mm["integration_token"],
                   "MATTERMOST_BOT_ID": mm["bot_user_id"], "SLASH_TOKEN": mm["command"]["token"],
                   "SLASH_ACS_TOKEN": mm["acs_command"]["token"], "MATTERMOST_IDENTITY_MAP": json.dumps(mappings)})


def fetch_chart(name):
    dest = LOCAL / "vendor" / (name+".tgz")
    dest.parent.mkdir(parents=True, exist_ok=True)
    base = "https://raw.githubusercontent.com/stackrox/helm-charts/main/opensource/"
    version = VERSIONS["stackrox_chart"]
    index = urlopen(base+"index.yaml", timeout=30).read().decode()
    section = index.split("  "+name+":\n", 1)[1].split("\n  stackrox-", 1)[0]
    entries = section.split("  - apiVersion:")
    entry = next(e for e in entries if "    version: "+version+"\n" in e)
    expected = re.search(r"    digest: ([a-f0-9]{64})", entry).group(1)
    if not dest.exists():
        dest.write_bytes(urlopen(base+name+"-"+version+".tgz", timeout=60).read())
    if hashlib.sha256(dest.read_bytes()).hexdigest() != expected:
        raise RuntimeError("Helm chart checksum mismatch: "+name)
    return dest


def install_stackrox(creds):
    values = {"env": {"openshift": False}, "central": {"telemetry": {"enabled": False},
              "adminPassword": {"value": creds["stackrox"]},
              "resources": resources("512Mi", "2Gi", "250m"),
              "persistence": {"persistentVolumeClaim": {"createClaim": True, "size": "1Gi"}},
              "exposure": {"nodePort": {"enabled": True, "port": 30443}},
              "db": {"resources": resources("512Mi", "1500Mi", "250m"),
                     "persistence": {"persistentVolumeClaim": {"createClaim": True, "size": "3Gi"}}}},
              "scanner": {"replicas": 1, "autoscaling": {"disable": True}, "resources": resources("384Mi", "2Gi", "250m"),
                          "dbResources": resources("512Mi", "3Gi", "100m")},
              "scannerV4": {"disable": True}}
    # Official Central DB defaults assume a larger cluster. Tune the same
    # configuration (including TLS) down for this two-namespace local lab.
    import tarfile
    chart = fetch_chart("stackrox-central-services")
    with tarfile.open(chart) as t:
        member = next(m for m in t.getmembers() if m.name.endswith("config/centraldb/postgresql.conf.default"))
        pg = t.extractfile(member).read().decode()
    for old, new in [("shared_buffers = 2GB", "shared_buffers = 128MB"), ("work_mem = 40MB", "work_mem = 4MB"),
                     ("maintenance_work_mem = 512MB", "maintenance_work_mem = 64MB"),
                     ("effective_cache_size = 4GB", "effective_cache_size = 512MB"), ("max_wal_size = 5GB", "max_wal_size = 512MB"),
                     ("autovacuum_max_workers = 5", "autovacuum_max_workers = 2")]:
        pg = pg.replace(old, new)
    values["central"]["db"]["postgresConfig"] = pg
    existing_pvcs = json.loads(kube("get", "pvc", "-A", "-o", "json", capture=True)).get("items", [])
    if any(p["metadata"]["namespace"] == "stackrox" and p["metadata"]["name"] == "central-db" for p in existing_pvcs):
        values["central"]["db"]["persistence"]["persistentVolumeClaim"] = {"claimName": "central-db", "createClaim": False}
    private_json(LOCAL/"central-values.json", values)
    apply([obj("Namespace", "stackrox", namespace=None), pvc("cvebridge-scanner-db", "12Gi", namespace="stackrox")])
    run(["helm", "upgrade", "--install", "stackrox-central-services", chart, "--kubeconfig", KUBECONFIG,
         "--namespace", "stackrox", "--create-namespace", "-f", LOCAL/"central-values.json",
         "--post-renderer", ROOT/"scripts/helm_postrender.py", "--timeout", "15m"], timeout=1000)
    kube("-n", "stackrox", "rollout", "status", "deploy/central", "--timeout=600s")
    # roxctl consumes the admin password from stdin, never an argv or log line.
    command = ["kubectl", "--kubeconfig", KUBECONFIG, "-n", "stackrox", "exec", "-i", "deploy/central", "--", "sh", "-c",
               'ROX_ADMIN_PASSWORD="$(cat)"; export ROX_ADMIN_PASSWORD; roxctl --insecure-skip-tls-verify central init-bundles generate cvebridge --output -']
    init_path = LOCAL / "init-bundle.yaml"
    if not init_path.exists():
        bundle = run(command, capture=True, input=creds["stackrox"])
        fd = os.open(init_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(bundle)
    secured = {"clusterName": "cvebridge-local", "centralEndpoint": "central.stackrox.svc:443",
               "sensor": {"resources": resources("256Mi", "768Mi", "150m")},
               "admissionControl": {"listenOnCreates": False, "listenOnUpdates": False, "resources": resources("64Mi", "256Mi", "50m")},
               "collector": {"collectionMethod": "NO_COLLECTION"}, "scannerV4": {"disable": True}, "scanner": {"disable": True}}
    private_json(LOCAL/"secured-values.json", secured)
    run(["helm", "upgrade", "--install", "stackrox-secured-cluster-services", fetch_chart("stackrox-secured-cluster-services"), "--kubeconfig", KUBECONFIG,
         "--namespace", "stackrox", "-f", init_path, "-f", LOCAL/"secured-values.json", "--wait", "--timeout", "10m"], timeout=700)


def bootstrap_stackrox(creds, schedule_namespaces=None):
    context = ssl._create_unverified_context()  # bootstrap ONLY, loopback, then pin CA
    base = "https://localhost:18443"
    basic = base64.b64encode(("admin:"+creds["stackrox"]).encode()).decode()
    def rox(path, payload=None, method=None):
        req = Request(base+path, data=None if payload is None else json.dumps(payload).encode(),
                      headers={"Authorization": "Basic "+basic, "Content-Type": "application/json"}, method=method)
        with urlopen(req, context=context, timeout=60) as r:
            return json.loads(r.read() or b"{}")
    clusters = rox("/v1/clusters").get("clusters", [])
    current = next((c for c in clusters if c["name"] == "cvebridge-local"), None)
    if not current:
        raise RuntimeError("StackRox has not registered the local secured cluster yet. Rerun up.")
    state_path = LOCAL/"stackrox.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    if not state.get("token"):
        permission_sets = rox("/v1/permissionsets").get("permissionSets", [])
        permissions = next((p for p in permission_sets if p["name"] == "CVE Bridge Read Only"), None)
        if not permissions:
            permissions = rox("/v1/permissionsets", {"name": "CVE Bridge Read Only", "description": "Only read workload and image data",
                              "resourceToAccess": {"Deployment": "READ_ACCESS", "Image": "READ_ACCESS", "Cluster": "READ_ACCESS", "Namespace": "READ_ACCESS"}})
        scopes = rox("/v1/simpleaccessscopes").get("accessScopes", [])
        scope = next((s for s in scopes if s["name"] == "CVE Bridge Local Cluster"), None)
        if not scope:
            scope = rox("/v1/simpleaccessscopes", {"name": "CVE Bridge Local Cluster", "rules": {"includedClusterIds": [current["id"]]}})
        roles = rox("/v1/roles").get("roles", [])
        if not any(r["name"] == "CVE Bridge Reader" for r in roles):
            rox("/v1/roles/CVE%20Bridge%20Reader", {"name": "CVE Bridge Reader", "permissionSetId": permissions["id"], "accessScopeId": scope["id"]})
        token = rox("/v1/apitokens/generate", {"name": "cvebridge-read-only", "role": "CVE Bridge Reader"})
        state = {"token": token["token"], "cluster_id": current["id"]}
    state["cluster_id"] = current["id"]
    # StackRox requires Image write permission to force a scan, and
    # Administration read permission to read the definitions timestamp.
    # Keep these capabilities on distinct tokens; the browser never gets them.
    permission_sets = rox("/v1/permissionsets").get("permissionSets", [])
    scopes = rox("/v1/simpleaccessscopes").get("accessScopes", [])
    scope = next(s for s in scopes if s["name"] == "CVE Bridge Local Cluster")
    roles = rox("/v1/roles").get("roles", [])
    for key, role, resources_map in [
        ("scan_token", "ACS Image Scanner", {"Image": "READ_WRITE_ACCESS"}),
        ("status_token", "ACS Database Status", {"Administration": "READ_ACCESS"})]:
        if state.get(key):
            continue
        permissions = next((p for p in permission_sets if p["name"] == role), None)
        if not permissions:
            permissions = rox("/v1/permissionsets", {"name": role, "resourceToAccess": resources_map})
        if not any(r["name"] == role for r in roles):
            rox("/v1/roles/"+quote(role, safe=""), {"name": role, "permissionSetId": permissions["id"], "accessScopeId": scope["id"]})
        state[key] = rox("/v1/apitokens/generate", {"name": key.replace("_", "-"), "role": role})["token"]
    schedule_namespaces = sorted(set(schedule_namespaces or ["demo-team-a", "demo-team-b", "demo-shared"]))
    schedule_rules = {"includedNamespaces":[{"clusterId":current["id"], "namespaceName":n} for n in schedule_namespaces]}
    scheduled_scope = next((s for s in scopes if s["name"] == "ACS Local Scheduled Namespaces"), None)
    if not scheduled_scope:
        scheduled_scope = rox("/v1/simpleaccessscopes", {"name":"ACS Local Scheduled Namespaces", "rules":schedule_rules})
    elif scheduled_scope.get("rules") != schedule_rules:
        rox("/v1/simpleaccessscopes/"+scheduled_scope["id"], {"name":"ACS Local Scheduled Namespaces", "rules":schedule_rules}, method="PUT")
    if not state.get("schedule_token"):
        name = "ACS Scheduled Reporter"
        permissions = next((p for p in permission_sets if p["name"] == name), None)
        if not permissions:
            permissions = rox("/v1/permissionsets", {"name":name,"resourceToAccess":{
                "Image":"READ_WRITE_ACCESS", "Deployment":"READ_ACCESS", "Cluster":"READ_ACCESS", "Namespace":"READ_ACCESS"}})
        if not any(r["name"] == name for r in roles):
            rox("/v1/roles/"+quote(name,safe=""), {"name":name,"permissionSetId":permissions["id"],"accessScopeId":scheduled_scope["id"]})
        state["schedule_token"] = rox("/v1/apitokens/generate", {"name":"acs-scheduled-reporter","role":name})["token"]
    private_json(state_path, state)
    secret_data = json.loads(kube("-n", "stackrox", "get", "secret", "central-tls", "-o", "json", capture=True))["data"]
    cert = base64.b64decode(secret_data["ca.pem"]).decode()
    (LOCAL/"central-ca.pem").write_text(cert)
    apply([secret("cvebridge-rox-ca", {"ca.pem": cert})])
    return state


def up():
    for name in ["docker", "k3d", "kubectl", "helm"]:
        if not shutil.which(name):
            raise RuntimeError("Required tool is missing: "+name)
    try:
        import bcrypt
    except ImportError:
        raise RuntimeError("Install the bootstrap dependency: python3 -m pip install bcrypt==5.0.0") from None
    LOCAL.mkdir(exist_ok=True, mode=0o700)
    minimum_disk = (3 if KUBECONFIG.exists() else 25)*1024**3
    if shutil.disk_usage(ROOT).free < minimum_disk:
        raise RuntimeError("Insufficient free disk for this installation/update. No other project's data will be deleted.")
    prefix = privileged()
    creds = credentials()
    print("[1/7] Preparing the isolated local Kubernetes cluster", flush=True)
    cluster(prefix)
    print("[2/7] Building the application image", flush=True)
    run(prefix+["docker", "build", "-f", "app/Dockerfile", "-t", VERSIONS["app"], "."])
    settings = local_settings()
    if (LOCAL/"settings.json").exists():
        previous = json.loads((LOCAL/"settings.json").read_text())
        for key in ["mattermost_channel_scopes", "mattermost_channel_policies", "mattermost_schedule_scopes", "mattermost_schedule_managers",
                    "cve_alerts_enabled", "cve_alert_min_cvss", "cve_alert_first_report"]:
            settings[key] = previous.get(key, settings.get(key, {}))
    # Install the namespace and dependencies first; application waits for secrets.
    apply([obj("Namespace", NS, namespace=None)])
    apply(demo_manifests(creds))
    print("[3/7] Starting Mattermost and the OIDC test login service", flush=True)
    for name in ["postgres", "mattermost", "dex"]:
        kube("-n", NS, "rollout", "status", "deploy/"+name, "--timeout=600s")
    mm = bootstrap_mattermost(creds)
    settings["mattermost_channel_scopes"][mm["shared_channel_id"]] = ["demo-team-a", "demo-team-b", "demo-shared"]
    settings["mattermost_channel_policies"][mm["shared_channel_id"]] = "requester"
    settings["mattermost_schedule_scopes"][mm["shared_channel_id"]] = ["demo-team-a", "demo-team-b", "demo-shared"]
    print("[4/7] Installing StackRox Central, Scanner and Sensor", flush=True)
    install_stackrox(creds)
    rox = bootstrap_stackrox(creds, [n for scope in settings["mattermost_schedule_scopes"].values() for n in scope])
    settings["stackrox_cluster_id"] = rox["cluster_id"]
    private_json(LOCAL/"settings.json", settings)
    print("[5/7] Connecting authentication, real RBAC and the slash command", flush=True)
    # Import immediately before scheduling: kubelet may garbage-collect an
    # unused local image while the slower upstream services are booting.
    run(prefix+["k3d", "image", "import", VERSIONS["app"], "--cluster", CLUSTER])
    apply([integration_secret(mm, rox),
           secret("cvebridge-proxy", {"OAUTH2_PROXY_CLIENT_SECRET": creds["oidc_client_secret"], "OAUTH2_PROXY_COOKIE_SECRET": creds["cookie_secret"]})])
    apply(common_manifests(settings))
    kube("-n", NS, "rollout", "restart", "deploy/cvebridge")
    kube("-n", NS, "rollout", "status", "deploy/cvebridge", "--timeout=300s")
    # Service endpoints and the Docker load balancer can take a moment to
    # converge after pod readiness. Verify HTTP before starting browser tests.
    for attempt in range(30):
        try:
            with urlopen(settings["public_url"], timeout=10) as response:
                if response.status == 200:
                    break
        except (OSError, HTTPError, URLError):
            pass
        if attempt == 29:
            raise RuntimeError("The protected browser endpoint did not become reachable")
        time.sleep(2)
    print("[6/7] Checking services and namespace boundaries", flush=True)
    run([sys.executable, "scripts/verify.py"], timeout=2400)
    verified = json.loads((LOCAL/"verification.json").read_text())
    print("[7/7] Installation complete. Open http://localhost:18065 and run /acs "+verified["example_cve"], flush=True)
    print("Private test passwords: .local/credentials.json (not tracked by Git)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["up", "status", "stop", "start", "render"])
    parser.add_argument("--config")
    args = parser.parse_args()
    if args.command == "up":
        up()
    elif args.command == "status":
        kube("get", "deploy", "-A")
    elif args.command in ["start", "stop"]:
        run(privileged()+["k3d", "cluster", args.command, CLUSTER])
    elif args.command == "render":
        if not args.config:
            parser.error("render requires --config path/to/settings.json")
        settings = json.loads(Path(args.config).read_text())
        if settings.get("node_port") is None and not settings["public_url"].startswith("https://"):
            raise RuntimeError("Enterprise configuration requires HTTPS")
        print(json.dumps({"apiVersion": "v1", "kind": "List", "items": common_manifests(settings)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print("Installation stopped:", str(exc), file=sys.stderr)
        sys.exit(1)
