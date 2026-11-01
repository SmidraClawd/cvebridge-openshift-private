"""Behavior checks for fresh scans, freshness reporting and disclosure policy."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("commands_server", Path(__file__).parents[1]/"app/server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class CommandsTests(unittest.TestCase):
    digest = "sha256:"+"a"*64

    def setUp(self):
        self.services = server.Services()
        self.services.cluster_id = "cluster-a"

    def test_old_definitions_are_stale_not_claimed_current(self):
        self.services.rox_request = lambda *a, **kw: {"lastUpdatedTimestamp": "2020-01-01T00:00:00Z"}
        result = self.services.database_status()
        self.assertEqual(result["state"], "stale")
        self.assertGreater(result["ageHours"], result["maxAgeHours"])
        self.assertIn("behöver uppdateras", server.status_message(result)["attachments"][0]["title"])

    def test_unknown_or_future_definition_time_does_not_claim_current(self):
        for data in [{}, {"lastUpdatedTimestamp": "2099-01-01T00:00:00Z"}, {"lastUpdatedTimestamp": "bad-date"}]:
            self.services.rox_request = lambda *a, **kw: data
            self.assertEqual(self.services.database_status()["state"], "unknown")
        def unavailable(*args, **kwargs):
            raise server.Problem(502, "Unavailable")
        self.services.rox_request = unavailable
        self.assertEqual(self.services.database_status()["state"], "unknown")

    def inventory_api(self, path):
        if path.startswith("/v1/pods?"):
            return {"pods": [{"id": "pod-a", "namespace": "team-a", "clusterId": "cluster-a", "deploymentId": "deploy-a",
                              "liveInstances": [{"containerName": "app", "imageDigest": self.digest}]}]}
        return {"name": "workload", "namespace": "team-a", "clusterId": "cluster-a", "containers": [
            {"name": "app", "image": {"name": {"fullName": "registry.example:5000/team/app:latest"}}}]}

    def test_inventory_pins_runtime_digest_preserving_registry_port(self):
        self.services.rox_request = self.inventory_api
        inventory = self.services.inventory(["team-a"])
        self.assertEqual(inventory["images"][0]["imageName"], "registry.example:5000/team/app@"+self.digest)
        self.assertEqual(inventory["pods"], 1)

    def test_out_of_scope_pod_never_becomes_scan_input(self):
        self.services.rox_request = lambda path: {"pods": [{"namespace": "secret", "clusterId": "cluster-a"}]}
        with self.assertRaises(server.Problem):
            self.services.inventory(["team-a"])

    def scan_setup(self, scan_time=None, fail=False):
        self.services.inventory = lambda ns: {"images": [{"digest": self.digest, "imageName": "registry/app@"+self.digest,
            "targets": [{"namespace": "team-a", "deployment": "app"}]}], "pods": 2, "missing": 0}
        self.services.database_status = lambda: {"state": "unknown", "lastUpdated": None}
        def rox(path, payload, **kwargs):
            self.assertEqual(path, "/v1/images/scan")
            self.assertIs(payload["force"], True)
            self.assertEqual(kwargs["capability"], "scan")
            if fail:
                raise server.Problem(502, "Scanner unavailable")
            return {"id": self.digest, "scan": {"scanTime": scan_time or server.utc_now(), "components": [
                {"name": "log4j-core", "version": "2.14.1", "vulns": [{"cve": "CVE-2021-44228", "cvss": 10, "fixedBy": "2.17.1"}]}]}}
        self.services.rox_request = rox

    def test_force_scan_collects_language_package_cves(self):
        self.scan_setup()
        result = self.services.scan(["team-a"], lambda: None, lambda p: None)
        self.assertEqual(result["scannedImages"], 1)
        self.assertEqual(result["rows"][0]["component"], "log4j-core")
        self.assertEqual(result["rows"][0]["cve"], "CVE-2021-44228")

    def test_failed_or_old_scan_is_reported_incomplete_not_reused(self):
        for old_time, fail in [("2020-01-01T00:00:00Z", False), (None, True)]:
            self.scan_setup(old_time, fail)
            result = self.services.scan(["team-a"], lambda: None, lambda p: None)
            self.assertEqual(result["scannedImages"], 0)
            self.assertEqual(result["failedImages"], 1)
            self.assertEqual(result["rows"], [])
            self.assertIn("luckor", server.scan_message(result)["attachments"][0]["title"])

    def test_report_mode_reads_existing_results_without_posting_a_scan(self):
        self.scan_setup("2020-01-01T00:00:00Z")
        image = {"id":self.digest,"scan":{"scanTime":"2020-01-01T00:00:00Z","components":[
            {"name":"log4j","version":"2.14.1","source":"JAVA","vulns":[{"cve":"CVE-2021-44228","cvss":10}]}]}}
        calls = []
        def read(path, *args, **kwargs):
            calls.append((path,args,kwargs))
            return image
        self.services.rox_request = read
        result = self.services.scan(["team-a"],lambda:None,lambda p:None,force=False)
        self.assertEqual(result["mode"],"report")
        self.assertEqual(result["scannedImages"],1)
        self.assertTrue(calls[0][0].startswith("/v1/images/sha256"))
        self.assertEqual(calls[0][1],())
        self.assertEqual(result["rows"][0]["source"],"JAVA")

    def test_missing_language_cves_is_visible_as_partial_coverage(self):
        self.scan_setup()
        original = self.services.rox_request
        def partial(*args, **kwargs):
            data = original(*args, **kwargs)
            data["scan"]["notes"] = ["LANGUAGE_CVES_UNAVAILABLE"]
            return data
        self.services.rox_request = partial
        result = self.services.scan(["team-a"], lambda: None, lambda p: None)
        self.assertEqual(result["partialImages"], 1)
        card = server.scan_message(result)["attachments"][0]
        self.assertIn("luckor", card["title"])
        self.assertIn("språkpaketens sårbarheter saknas", card["text"])

    def test_permission_revocation_stops_further_scanning(self):
        self.scan_setup()
        def revoked():
            raise server.Problem(403, "Revoked")
        with self.assertRaises(server.Problem):
            self.services.scan(["team-a"], revoked, lambda p: None)

    def test_job_ownership_and_restart_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            store = server.Store(directory+"/jobs.db")
            job_id = store.create_job("alice@demo.local")
            with self.assertRaises(server.Problem):
                store.get_job(job_id, "bob@demo.local")
            server.ScanRunner(self.services, store)
            self.assertEqual(store.get_job(job_id, "alice@demo.local")["state"], "failed")

    def test_worker_rechecks_before_delivering_and_blocks_changed_audience(self):
        channel, alice, bot = "c"*26, "a"*26, "s"*26
        with tempfile.TemporaryDirectory() as directory:
            store = server.Store(directory+"/jobs.db")
            runner = server.ScanRunner(self.services, store)
            job_id = store.create_job("alice@demo.local")
            self.services.allowed_namespaces = lambda *a: ["team-a"]
            self.services.shared_audience = lambda *a: {"namespaces": ["team-a"], "members": [alice, bot, "b"*26], "policy": "requester"}
            self.services.send_callback = lambda *a, **kw: self.fail("Revoked audience received a result")
            self.scan_setup()
            runner.lock.acquire()
            runner.run(job_id, {"email": "alice@demo.local", "channel_id": channel, "mm_user_id": alice},
                       "alice@demo.local", [], ["team-a"], {"namespaces": ["team-a"], "members": [alice, bot], "policy": "requester"})
            self.assertEqual(store.get_job(job_id, "alice@demo.local")["state"], "failed")


if __name__ == "__main__":
    unittest.main()
