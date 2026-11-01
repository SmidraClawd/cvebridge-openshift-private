import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("openshift_server", Path(__file__).parents[1]/"app/server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class OpenShiftAuthTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {
            "AUTH_PROVIDER":"openshift", "STACKROX_CLUSTER_ID":"cluster-a",
            "MATTERMOST_KUBE_USER_MAP":json.dumps({"a"*26:"Alice"}),
            "MATTERMOST_CHANNEL_SCOPES":"{}", "MATTERMOST_CHANNEL_POLICIES":"{}",
            "MATTERMOST_SCHEDULE_SCOPES":"{}", "MATTERMOST_SCHEDULE_MANAGERS":"{}"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.services = server.Services()
        self.review_calls = []
        self.revoked = False
        self.services.kube_request = self.kube_request
        self.services.mm_request = lambda path: {"id":"a"*26, "username":"editable-name", "delete_at":0}
        self.services.send_callback = Mock()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = server.Store(self.directory.name+"/requests.db")

    def kube_request(self, path, payload=None):
        if path.endswith("/tokenreviews"):
            token = payload["spec"]["token"]
            self.review_calls.append(token)
            if token == "expired-token":
                return {"status":{"authenticated":False}}
            username = {"alice-token":"Alice", "bob-token":"Bob"}.get(token)
            return {"status":{"authenticated":bool(username), "user":{
                "username":username, "groups":[] if self.revoked else ["developers", "system:authenticated"]}}}
        if payload is None:
            return {"items":[{"metadata":{"name":"team-a"}},{"metadata":{"name":"restricted"}}]}
        allowed = payload["spec"]["resourceAttributes"]["namespace"] == "team-a" and "developers" in payload["spec"]["groups"]
        return {"status":{"allowed":allowed}}

    def request(self, path, headers):
        handler = type("OpenShiftHandler", (server.Handler,), {
            "services":self.services, "store":self.store, "public_listener":False})
        self.services.lookup = lambda cve, namespaces: {"cve":cve, "namespaces":namespaces,
            "rows":[], "scannedImages":1, "unscannedImages":0}
        httpd = server.ThreadingHTTPServer(("127.0.0.1",0),handler)
        thread = threading.Thread(target=httpd.serve_forever,daemon=True)
        thread.start()
        try:
            client = http.client.HTTPConnection("127.0.0.1",httpd.server_port,timeout=5)
            client.request("GET",path,headers=headers)
            response = client.getresponse()
            result = response.status,response.read().decode()
            client.close()
            return result
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def test_browser_owner_and_groups_come_from_token_review_without_email(self):
        owner = self.services.expected_user("a"*26)
        request_id = self.store.create(owner,"CVE-2021-44228","team-a","/hooks/commands/test")
        status,body = self.request("/requests/"+request_id, {
            "X-Forwarded-Access-Token":"alice-token", "X-Forwarded-User":"cluster-admin",
            "X-Forwarded-Email":"forged@example.org", "X-Forwarded-Groups":"system:masters"})
        self.assertEqual(status,200)
        self.assertIn("Alice",body)
        self.assertNotIn("cluster-admin",body)
        self.assertGreaterEqual(len(self.review_calls),2)
        self.services.send_callback.assert_called_once()
        result = self.services.send_callback.call_args.args[1]
        self.assertEqual(result["namespaces"],["team-a"])
        self.assertNotIn(b"alice-token",Path(self.store.path).read_bytes())
        self.assertNotIn("alice-token",body+json.dumps(result))

    def test_another_token_cannot_claim_a_link_using_spoofed_headers(self):
        request_id = self.store.create("openshift:Alice","CVE-2021-44228","team-a","/hooks/commands/test")
        status,_ = self.request("/requests/"+request_id, {
            "X-Forwarded-Access-Token":"bob-token", "X-Forwarded-User":"Alice",
            "X-Forwarded-Email":"Alice", "X-Forwarded-Groups":"developers"})
        self.assertEqual(status,403)
        self.services.send_callback.assert_not_called()

    def test_missing_or_revoked_token_cannot_use_forwarded_identity(self):
        for token in ["","expired-token"]:
            status,_ = self.request("/", {"X-Forwarded-Access-Token":token,
                "X-Forwarded-User":"Alice", "X-Forwarded-Groups":"system:masters"})
            self.assertEqual(status,401)

    def test_header_groups_cannot_expand_namespace_access(self):
        status,_ = self.request("/search?cve=CVE-2021-44228&namespace=restricted", {
            "X-Forwarded-Access-Token":"alice-token", "X-Forwarded-Groups":"system:masters"})
        self.assertEqual(status,403)

    def test_user_mapping_uses_stable_mattermost_id_and_exact_openshift_name(self):
        self.assertEqual(self.services.expected_user("a"*26),"openshift:Alice")
        with self.assertRaises(server.Problem):
            self.services.expected_user("b"*26)
        self.assertEqual(server.login_account({},"Alice"),"openshift:Alice")

    def test_case_distinct_openshift_owners_do_not_share_requests_or_jobs(self):
        request_id = self.store.create("openshift:Alice","scan","team-a","/hooks/commands/test")
        job_id = self.store.create_job("openshift:Alice")
        for check,identifier in [(self.store.get,request_id),(self.store.get_job,job_id)]:
            check(identifier,"openshift:Alice")
            with self.assertRaises(server.Problem):
                check(identifier,"openshift:alice")

    def test_token_review_failure_does_not_fall_back_to_headers(self):
        self.services.kube_request = Mock(side_effect=server.Problem(503,"Unavailable"))
        status,_ = self.request("/", {"X-Forwarded-Access-Token":"alice-token", "X-Forwarded-User":"Alice"})
        self.assertEqual(status,503)

    def test_live_group_revocation_stops_background_scan_delivery(self):
        runner = server.ScanRunner(self.services,self.store)
        job_id = self.store.create_job("openshift:Alice")
        def scan(namespaces,authorize,progress):
            self.revoked = True
            authorize()
            self.fail("Revoked namespace must not be scanned")
        self.services.scan = scan
        refresh = lambda: server.identity({"X-Forwarded-Access-Token":"alice-token"},self.services)
        runner.lock.acquire()
        runner.run(job_id,{"email":"openshift:Alice"},"Alice",["developers"],["team-a"],None,refresh)
        self.assertEqual(self.store.get_job(job_id,"openshift:Alice")["state"],"failed")
        self.services.send_callback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
