import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("server", Path(__file__).parents[1]/"app/server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class SecurityTests(unittest.TestCase):
    def test_mattermost_token_and_bearer_schemes_are_supported(self):
        for authorization in ["Token command-secret", "Bearer command-secret", "bearer command-secret", ""]:
            server.verify_command_token("command-secret", authorization, "command-secret")
        server.verify_command_token("command-secret", "Token command-secret", "")

    def test_missing_wrong_or_conflicting_command_tokens_are_denied(self):
        for expected, authorization, form in [("", "Token x", "x"), ("x", "", ""),
                ("x", "Token wrong", "x"), ("x", "Bearer x", "wrong"),
                ("x", "Basic x", "x"), ("x", "Token", "x"), ("x", "Token ö", "")]:
            with self.assertRaises(server.Problem) as error:
                server.verify_command_token(expected, authorization, form)
            self.assertEqual(error.exception.status, 401)

    def test_identity_requires_proxy_identity_and_strips_privileged_groups(self):
        with self.assertRaises(server.Problem):
            server.identity({})
        user, groups = server.identity({"X-Forwarded-Email": "alice@demo.local", "X-Forwarded-Groups": "team-a,system:masters"})
        self.assertEqual(user, "alice@demo.local")
        self.assertEqual(groups, ["team-a", "system:authenticated"])

    def test_cve_cannot_inject_a_stackrox_search(self):
        for value in ["CVE-2024-1234+Namespace:secret", "CVE-2024-1234\nCluster:prod", "all"]:
            with self.assertRaises(server.Problem):
                server.validate_cve(value)
        self.assertEqual(server.validate_cve("cve-2024-1234"), "CVE-2024-1234")

    def test_namespace_cannot_escape_the_authorized_set(self):
        with self.assertRaises(server.Problem) as error:
            server.select_namespaces(["team-a"], "team-b")
        self.assertEqual(error.exception.status, 403)
        with self.assertRaises(server.Problem):
            server.select_namespaces([], "")

    def test_query_link_is_bound_to_owner_and_expires(self):
        with tempfile.TemporaryDirectory() as d:
            store = server.Store(d+"/requests.db")
            request_id = store.create("alice@demo.local", "CVE-2024-1234", "", "/hooks/commands/abc")
            with self.assertRaises(server.Problem) as error:
                store.get(request_id, "bob@demo.local")
            self.assertEqual(error.exception.status, 403)
            self.assertEqual(store.get(request_id, "alice@demo.local")["cve"], "CVE-2024-1234")
            with store.connect() as conn:
                conn.execute("UPDATE requests SET created=?", (time.time()-601,))
            with self.assertRaises(server.Problem):
                store.get(request_id, "alice@demo.local")

    def test_query_link_has_an_atomic_delivery_claim(self):
        with tempfile.TemporaryDirectory() as d:
            store = server.Store(d+"/requests.db")
            request_id = store.create("alice@demo.local", "CVE-2024-1234", "", "/hooks/commands/abc")
            store.claim(request_id)
            with self.assertRaises(server.Problem) as error:
                store.claim(request_id)
            self.assertEqual(error.exception.status, 409)
            store.release(request_id)
            store.claim(request_id)
            store.consume(request_id)
            with self.assertRaises(server.Problem):
                store.get(request_id, "alice@demo.local")

    def test_callback_url_is_not_a_general_purpose_proxy(self):
        services = server.Services()
        self.assertEqual(services.callback_path("http://localhost:18065/hooks/commands/abc123"), "/hooks/commands/abc123")
        for value in ["http://169.254.169.254/hooks/commands/a", "http://localhost:18065.evil.test/hooks/commands/a",
                      "http://localhost:18065/api/v4/users", "http://localhost:18065/hooks/commands/a?url=secret",
                      "http://user@localhost:18065/hooks/commands/a", "http://localhost:18065/hooks/commands/../a"]:
            with self.assertRaises(server.Problem):
                services.callback_path(value)

    def test_sar_evaluation_error_releases_no_namespaces(self):
        services = server.Services()
        calls = []
        def kube(path, payload=None):
            calls.append(payload)
            return {"items": [{"metadata": {"name": "team-a"}}]} if payload is None else {"status": {"allowed": True, "evaluationError": "incomplete"}}
        services.kube_request = kube
        with self.assertRaises(server.Problem):
            services.allowed_namespaces("alice@demo.local", [])
        self.assertEqual(calls[-1]["spec"]["user"], "alice@demo.local")
        self.assertEqual(calls[-1]["spec"]["resourceAttributes"]["resource"], "deployments")

    def test_stackrox_results_are_rechecked_for_cluster_and_namespace(self):
        services = server.Services()
        services.cluster_id = "cluster-a"
        paths = []
        def rox(path):
            paths.append(path)
            return {"deployments": [{"id": "secret", "namespace": "team-b", "clusterId": "cluster-a"},
                                    {"id": "other-cluster", "namespace": "team-a", "clusterId": "cluster-b"}]}
        services.rox_request = rox
        result = services.lookup("CVE-2024-1234", ["team-a"])
        self.assertEqual(result["rows"], [])
        self.assertEqual(len(paths), 1)
        self.assertIn("Namespace%3Ateam-a", paths[0])
        self.assertIn("Cluster+ID%3Acluster-a", paths[0])

    def test_pending_stackrox_scan_is_reported_as_missing_coverage(self):
        services = server.Services()
        services.cluster_id = "cluster-a"
        deployment = {"id": "deployment-a", "name": "sample-app", "namespace": "team-a", "clusterId": "cluster-a"}
        def rox(path):
            if path.startswith("/v1/deployments?"):
                return {"deployments": [deployment]}
            if path.startswith("/v1/deployments/"):
                return deployment | {"containers": [{"image": {"id": "sha256:sample"}}]}
            return {"id": "sha256:sample", "scan": None, "notes": None, "name": None}
        services.rox_request = rox
        result = services.lookup("CVE-2024-1234", ["team-a"])
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["scannedImages"], 0)
        self.assertEqual(result["unscannedImages"], 1)

    def test_command_email_is_resolved_from_mattermost_api(self):
        services = server.Services()
        services.mm_request = lambda path: {"email": "alice@demo.local", "email_verified": True, "delete_at": 0}
        self.assertEqual(services.expected_user("a"*26), "alice@demo.local")
        with self.assertRaises(server.Problem):
            services.expected_user("../../etc/passwd")
        services.mm_request = lambda path: {"email": "victim@demo.local", "email_verified": False, "delete_at": 0}
        with self.assertRaises(server.Problem):
            services.expected_user("a"*26)
        with patch.dict(os.environ, {"MATTERMOST_IDENTITY_MAP": '{"aaaaaaaaaaaaaaaaaaaaaaaaaa":"alice@demo.local"}'}):
            self.assertEqual(services.expected_user("a"*26), "alice@demo.local")

    def test_results_sent_to_mattermost_are_ephemeral(self):
        services = server.Services()
        with patch.object(server, "request_json") as request:
            services.send_callback("/hooks/commands/abc", {"cve": "CVE-2024-1234", "rows": [], "scannedImages": 1, "unscannedImages": 0})
            self.assertEqual(request.call_args.kwargs["payload"]["response_type"], "ephemeral")
            self.assertFalse(request.call_args.kwargs["expect_json"])

    def test_plain_text_callback_ack_does_not_relax_json_data_apis(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"ok"
        with patch.object(server, "urlopen", return_value=response):
            self.assertEqual(server.request_json("http://callback.local", payload={}, expect_json=False), {})
            with self.assertRaises(server.Problem):
                server.request_json("http://data-api.local")


if __name__ == "__main__":
    unittest.main()
