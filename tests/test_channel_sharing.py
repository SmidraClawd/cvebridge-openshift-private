import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("sharing_server", Path(__file__).parents[1]/"app/server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class ChannelSharingTests(unittest.TestCase):
    channel = "c"*26
    alice, bob, integration = "a"*26, "b"*26, "s"*26

    def setUp(self):
        self.environment = patch.dict(os.environ, {
            "MATTERMOST_CHANNEL_SCOPES": json.dumps({self.channel: ["team-a", "team-b", "common"]}),
            "MATTERMOST_IDENTITY_MAP": json.dumps({self.alice: "alice@demo.local", self.bob: "bob@demo.local"}),
            "MATTERMOST_KUBE_USER_MAP": "{}", "IDENTITY_HEADER": "X-Forwarded-Email", "IDENTITY_PREFIX": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.services = server.Services()
        self.services.bot_id = self.integration
        self.members = [self.integration, self.alice, self.bob]
        self.channel_type = "P"
        self.permissions = {"alice@demo.local": {"team-a", "common"}, "bob@demo.local": {"team-b", "common"}}
        self.checked = []
        def mm(path):
            if path == "/api/v4/users/me":
                return {"id": self.integration, "is_bot": True, "roles": "system_user"}
            if path == "/api/v4/channels/"+self.channel:
                return {"id": self.channel, "type": self.channel_type}
            if "/members?" in path:
                return [{"channel_id": self.channel, "user_id": m} for m in self.members]
            return {"email": "editable@untrusted.local", "email_verified": False}
        def permitted(user, groups, namespace):
            self.checked.append((user, groups, namespace))
            return namespace in self.permissions.get(user, set())
        self.services.mm_request = mm
        self.services.permitted_namespace = permitted

    def test_shared_scope_is_the_intersection_of_every_member_and_channel_policy(self):
        audience = self.services.shared_audience(self.channel, self.alice, ["team-a", "common", "outside"])
        self.assertEqual(audience["namespaces"], ["common"])
        self.assertEqual(audience["members"], sorted(self.members))
        self.assertTrue(self.checked)
        self.assertTrue(all(groups == ["system:authenticated"] for _, groups, _ in self.checked))

    def test_requester_policy_shares_only_caller_access_inside_approved_scope(self):
        self.services.channel_policies[self.channel] = "requester"
        audience = self.services.shared_audience(self.channel, self.alice, ["team-a", "common", "outside"])
        self.assertEqual(audience["namespaces"], ["common", "team-a"])
        self.assertEqual(audience["policy"], "requester")
        self.assertEqual(self.checked, [])
        self.members.append("u"*26)
        with self.assertRaises(server.Problem):
            self.services.shared_audience(self.channel, self.alice, ["team-a"])

    def test_unapproved_channels_stay_private_and_public_channels_cannot_share(self):
        self.assertIsNone(self.services.shared_audience("z"*26, self.alice, ["common"]))
        self.channel_type = "O"
        with self.assertRaises(server.Problem) as error:
            self.services.shared_audience(self.channel, self.alice, ["common"])
        self.assertEqual(error.exception.status, 403)

    def test_unknown_member_blocks_sharing_instead_of_using_profile_email(self):
        self.members.append("u"*26)
        with self.assertRaises(server.Problem) as error:
            self.services.shared_audience(self.channel, self.alice, ["common"])
        self.assertEqual(error.exception.status, 403)

    def test_members_without_common_permissions_block_sharing(self):
        self.permissions["bob@demo.local"] = {"team-b"}
        with self.assertRaises(server.Problem) as error:
            self.services.shared_audience(self.channel, self.alice, ["team-a", "common"])
        self.assertEqual(error.exception.status, 403)

    def test_requester_and_integration_must_still_be_channel_members(self):
        for missing in [self.alice, self.integration]:
            self.members = [m for m in [self.alice, self.bob, self.integration] if m != missing]
            with self.assertRaises(server.Problem):
                self.services.shared_audience(self.channel, self.alice, ["common"])

    def test_non_email_kubernetes_identity_requires_explicit_member_mapping(self):
        with patch.dict(os.environ, {"IDENTITY_HEADER": "X-Forwarded-User"}):
            with self.assertRaises(server.Problem):
                self.services.shared_audience(self.channel, self.alice, ["common"])
            mapping = {self.alice: "alice-kube", self.bob: "bob-kube"}
            self.permissions.update({"alice-kube": {"common"}, "bob-kube": {"common"}})
            with patch.dict(os.environ, {"MATTERMOST_KUBE_USER_MAP": json.dumps(mapping)}):
                self.assertEqual(self.services.shared_audience(self.channel, self.alice, ["common"])["namespaces"], ["common"])

    def test_existing_private_request_is_preserved_by_database_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory+"/old.db"
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TABLE requests (id TEXT PRIMARY KEY, created REAL, email TEXT, cve TEXT, namespace TEXT, callback TEXT)")
                connection.execute("INSERT INTO requests VALUES (?,?,?,?,?,?)", ("old", time.time(), "alice@demo.local", "CVE-2022-40897", "", "/hooks/commands/abc"))
            connection.close()
            store = server.Store(path)
            row = store.get("old", "alice@demo.local")
            self.assertEqual(row["channel_id"], "")
            self.assertEqual(row["mm_user_id"], "")
            self.assertEqual(row["shared_requested"], 0)

    def test_private_request_cannot_turn_shared_after_a_configuration_change(self):
        with tempfile.TemporaryDirectory() as directory:
            store = server.Store(directory+"/requests.db")
            request_id = store.create("alice@demo.local", "CVE-2022-40897", "", "/hooks/commands/abc", self.channel, self.alice)
            handler = object.__new__(server.Handler)
            handler.path = "/requests/"+request_id
            handler.headers = {"X-Forwarded-Email": "alice@demo.local"}
            handler.store = store
            handler.services = MagicMock()
            handler.services.allowed_namespaces.return_value = ["common"]
            handler.services.lookup.return_value = {"cve": "CVE-2022-40897", "rows": [], "scannedImages": 0, "unscannedImages": 0}
            handler.reply = MagicMock()
            handler.do_GET()
            self.assertEqual(handler.reply.call_args.args[0], 200)
            handler.services.shared_audience.assert_not_called()
            self.assertFalse(handler.services.send_callback.call_args.kwargs["shared"])

    def test_audience_change_during_lookup_prevents_any_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            store = server.Store(directory+"/requests.db")
            request_id = store.create("alice@demo.local", "CVE-2022-40897", "", "/hooks/commands/abc", self.channel, self.alice, shared=True)
            handler = object.__new__(server.Handler)
            handler.path = "/requests/"+request_id
            handler.headers = {"X-Forwarded-Email": "alice@demo.local"}
            handler.store = store
            handler.services = MagicMock()
            handler.services.allowed_namespaces.return_value = ["common"]
            handler.services.shared_audience.side_effect = [
                {"namespaces": ["common"], "members": [self.alice, self.bob]},
                {"namespaces": ["common"], "members": [self.alice, self.bob, "u"*26]}]
            handler.reply = MagicMock()
            handler.do_GET()
            self.assertEqual(handler.reply.call_args.args[0], 403)
            handler.services.send_callback.assert_not_called()
            self.assertEqual(store.get(request_id, "alice@demo.local")["claimed"], 0)

    def test_shared_result_is_posted_as_the_authenticated_acs_bot(self):
        with patch.object(self.services, "mm_request", side_effect=[{"id": self.integration, "is_bot": True, "roles": "system_user"}, {"id": "post-id"}]) as request:
            self.services.send_callback("/hooks/commands/abc", {"cve": "CVE-2022-40897", "rows": [], "scannedImages": 1, "unscannedImages": 0}, shared=True, channel_id=self.channel)
            payload = request.call_args.args[1]
            self.assertTrue(request.call_args.args[0].endswith("/api/v4/posts"))
            self.assertEqual(payload["channel_id"], self.channel)
            self.assertIn("attachments", payload["props"])
            self.assertNotIn("user_id", payload)

    def test_human_or_admin_tokens_cannot_be_used_as_the_acs_bot(self):
        for profile in [{"id": self.integration, "is_bot": False, "roles": "system_user"},
                        {"id": self.integration, "is_bot": True, "roles": "system_admin system_user"},
                        {"id": self.alice, "is_bot": True, "roles": "system_user"}]:
            with patch.object(self.services, "mm_request", return_value=profile):
                with self.assertRaises(server.Problem):
                    self.services.bot_profile()


if __name__ == "__main__":
    unittest.main()
