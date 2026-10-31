import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("deployment", Path(__file__).parents[1]/"scripts/platform.py")
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


class DeploymentTests(unittest.TestCase):
    def test_company_namespace_is_used_for_every_namespaced_resource(self):
        settings = deployment.local_settings() | {"namespace": "security-tools", "node_port": None,
                    "public_url": "https://cvebridge.example.org", "cookie_secure": True}
        items = deployment.common_manifests(settings)
        for item in items:
            if item["kind"] not in ["Namespace", "ClusterRole", "ClusterRoleBinding"]:
                self.assertEqual(item["metadata"]["namespace"], "security-tools")
        binding = next(i for i in items if i["kind"] == "ClusterRoleBinding")
        self.assertEqual(binding["subjects"][0]["namespace"], "security-tools")

    def test_openshift_uses_assigned_uids_and_keeps_browser_backend_private(self):
        settings = deployment.local_settings() | {"node_port": None, "public_url": "https://cvebridge.example.org", "cookie_secure": True}
        items = deployment.common_manifests(settings)
        pod = next(i for i in items if i["kind"] == "Deployment")["spec"]["template"]["spec"]
        self.assertNotIn("fsGroup", pod["securityContext"])
        for container in pod["containers"]:
            self.assertNotIn("runAsUser", container["securityContext"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        for item in items:
            if item["kind"] == "Service":
                self.assertNotIn(8000, [p["port"] for p in item["spec"]["ports"]])
        route = next(i for i in items if i["kind"] == "Route")
        self.assertEqual(route["spec"]["tls"]["insecureEdgeTerminationPolicy"], "Redirect")

    def test_reporter_has_only_explicit_namespace_grants_and_no_mounted_token(self):
        settings = deployment.local_settings() | {"mattermost_schedule_scopes":{"c"*26:["team-a"]}}
        items = deployment.common_manifests(settings)
        account = next(i for i in items if i["kind"] == "ServiceAccount" and i["metadata"]["name"] == "acs-reporter")
        self.assertIs(account["automountServiceAccountToken"],False)
        roles = [i for i in items if i["kind"] == "Role"]
        self.assertEqual(len(roles),1)
        self.assertEqual(roles[0]["metadata"]["namespace"],"team-a")
        self.assertEqual(roles[0]["rules"],[{"apiGroups":["apps"],"resources":["deployments"],"verbs":["list"]}])

    def test_native_openshift_auth_does_not_need_an_oidc_issuer(self):
        settings = deployment.local_settings() | {"namespace":"security-tools", "auth_provider":"openshift",
            "node_port":None, "public_url":"https://acs.company.test",
            "openshift_proxy_image":"registry.company.test/oauth-proxy@sha256:"+"a"*64}
        settings.pop("oidc_issuer")
        settings.pop("oidc_client_id")
        items = deployment.common_manifests(settings)
        pod = next(i for i in items if i["kind"] == "Deployment")["spec"]["template"]["spec"]
        proxy = next(c for c in pod["containers"] if c["name"] == "proxy")
        self.assertIn("--provider=openshift",proxy["args"])
        self.assertIn("--pass-access-token=true",proxy["args"])
        self.assertIn("--scope=user:info",proxy["args"])
        self.assertEqual(proxy["readinessProbe"]["httpGet"]["path"],"/oauth2/healthz")
        self.assertNotIn("--openshift-service-account=", " ".join(proxy["args"]))
        app = next(c for c in pod["containers"] if c["name"] == "app")
        self.assertEqual(next(e["value"] for e in app["env"] if e["name"] == "AUTH_PROVIDER"),"openshift")
        reviewer = next(i for i in items if i["kind"] == "ClusterRole")
        self.assertIn({"apiGroups":["authentication.k8s.io"],"resources":["tokenreviews"],"verbs":["create"]},reviewer["rules"])
        ca_reader = next(i for i in items if i["kind"] == "Role")
        self.assertEqual(ca_reader["metadata"]["namespace"],"openshift-config-managed")
        self.assertEqual(ca_reader["rules"][0]["resourceNames"],["oauth-serving-cert"])

    def test_public_webhook_route_does_not_expose_browser_backend(self):
        settings = deployment.local_settings() | {"node_port":None,
            "public_url":"https://acs.company.test", "webhook_public_url":"https://acs.company.test"}
        items = deployment.common_manifests(settings)
        hook = next(i for i in items if i["kind"] == "Route" and i["metadata"]["name"] == "cvebridge-webhook")
        self.assertEqual(hook["spec"]["path"],"/slash/cve")
        self.assertEqual(hook["spec"]["port"]["targetPort"],"webhook")
        self.assertEqual(hook["spec"]["to"]["name"],"cvebridge-webhook")
        for item in items:
            if item["kind"] == "Service":
                self.assertNotIn(8000,[p["targetPort"] for p in item["spec"]["ports"]])


if __name__ == "__main__":
    unittest.main()
