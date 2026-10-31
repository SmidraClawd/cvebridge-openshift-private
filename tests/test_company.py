import importlib.util
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("company", Path(__file__).parents[1]/"scripts/company.py")
company = importlib.util.module_from_spec(spec)
spec.loader.exec_module(company)


class CompanyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.path = self.base/"company.json"
        company.initialize(self.path)
        self.data = json.loads(self.path.read_text())
        self.data["settings"].update(app_image="registry.corp.test/cvebridge:v1",
            openshift_proxy_image="registry.corp.test/oauth-proxy:v1",
            public_url="https://cve.corp.test",webhook_public_url="https://cve.corp.test",
            mattermost_public_url="https://chat.corp.test",mattermost_internal_url="https://chat.corp.test",
            stackrox_url="https://central.corp.test",stackrox_cluster_id="cluster-123")
        self.data["credentials"].update(MATTERMOST_TOKEN="bot-private-token",MATTERMOST_BOT_ID="b"*26,
            SLASH_TOKEN="command-private-token",STACKROX_TOKEN="read-private-token",STACKROX_SCAN_TOKEN="scan-private-token",
            STACKROX_STATUS_TOKEN="status-private-token",MATTERMOST_KUBE_USER_MAP={"a"*26:"Alice"})

    def test_init_is_private_and_never_replaces_existing_credentials(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
        previous = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            company.initialize(self.path)
        self.assertEqual(self.path.read_bytes(),previous)

    def test_generated_oauth_client_matches_proxy_secret_and_native_owner_mapping(self):
        manifest = company.installation(self.data,self.base)
        self.assertEqual(manifest["items"][0]["kind"],"Namespace")
        client = next(i for i in manifest["items"] if i["kind"]=="OAuthClient")
        proxy = next(i for i in manifest["items"] if i["kind"]=="Secret" and i["metadata"]["name"]=="cvebridge-proxy")
        self.assertEqual(client["secret"],proxy["stringData"]["OAUTH2_PROXY_CLIENT_SECRET"])
        self.assertEqual(client["scopeRestrictions"],[{"literals":["user:info"]}])
        self.assertEqual(client["redirectURIs"],["https://cve.corp.test/oauth2/callback"])
        self.assertEqual(client["grantMethod"],"prompt")
        integration = next(i for i in manifest["items"] if i["kind"]=="Secret" and i["metadata"]["name"]=="cvebridge-integration")
        self.assertEqual(json.loads(integration["stringData"]["MATTERMOST_KUBE_USER_MAP"]),{"a"*26:"Alice"})
        self.assertNotIn("MATTERMOST_IDENTITY_MAP",integration["stringData"])

    def test_unapproved_schedule_scope_and_missing_reporter_credential_are_rejected(self):
        settings = self.data["settings"]
        settings.update(mattermost_channel_scopes={"c"*26:["team-a"]},mattermost_schedule_scopes={"c"*26:["restricted"]})
        self.data["credentials"]["STACKROX_SCHEDULE_TOKEN"]="scheduled-private-token"
        with self.assertRaisesRegex(company.ConfigError,"mattermost_schedule_scopes"):
            company.validate(self.data,self.base)
        settings["mattermost_schedule_scopes"]={"c"*26:["team-a"]}
        self.data["credentials"]["STACKROX_SCHEDULE_TOKEN"]=""
        with self.assertRaisesRegex(company.ConfigError,"STACKROX_SCHEDULE_TOKEN"):
            company.validate(self.data,self.base)

    def test_prepare_excludes_credentials_from_review_and_build_files(self):
        output = self.base/"install"
        company.prepare(self.data,self.base,output)
        for path in output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        review=(output/"deployment.json").read_text()
        self.assertNotIn("bot-private-token",review)
        self.assertNotIn(self.data["credentials"]["OAUTH2_PROXY_CLIENT_SECRET"],review)
        with tarfile.open(output/"app-source.tar.gz") as archive:
            self.assertEqual(set(archive.getnames()),{"Dockerfile","app/__init__.py","app/server.py","app/scheduling.py"})
            self.assertNotIn(b"bot-private-token",b"".join(archive.extractfile(i).read() for i in archive.getmembers()))

    def test_online_bot_discovery_accepts_existing_openshift_bot_and_rejects_admin(self):
        self.data["credentials"]["MATTERMOST_BOT_ID"]=""
        response=MagicMock()
        response.__enter__.return_value=response
        bot={"id":"b"*26,"is_bot":True,"username":"OpenShift","roles":"system_user"}
        response.read.return_value=json.dumps(bot).encode()
        with patch.object(company,"urlopen",return_value=response) as opened:
            company.resolve_bot(self.data,self.base)
        self.assertEqual(self.data["credentials"]["MATTERMOST_BOT_ID"],"b"*26)
        self.assertEqual(opened.call_args.args[0].get_method(),"GET")
        response.read.return_value=json.dumps(bot|{"roles":"system_user system_admin"}).encode()
        with patch.object(company,"urlopen",return_value=response),self.assertRaises(company.ConfigError):
            company.resolve_bot(self.data,self.base)

    def test_invalid_inputs_report_field_names_without_secret_values(self):
        token=self.data["credentials"]["MATTERMOST_TOKEN"]
        self.data["credentials"]["SLASH_TOKEN"]=token
        with self.assertRaises(company.ConfigError) as failure:
            company.validate(self.data,self.base)
        self.assertNotIn(token,str(failure.exception))
        self.assertIn("SLASH_TOKEN",str(failure.exception))
        self.data["credentials"]["SLASH_TOKEN"]="different-command-token"
        self.data["settings"]["public_url"]="http://unsafe.test"
        with self.assertRaisesRegex(company.ConfigError,"public_url"):
            company.validate(self.data,self.base)

    def test_custom_mattermost_ca_is_mounted_and_tls_verification_stays_enabled(self):
        (self.base/"corporate-ca.pem").write_text(company.ca_bundle(self.data,self.base,"mattermost_ca_file"))
        self.data["mattermost_ca_file"]="corporate-ca.pem"
        items=company.installation(self.data,self.base)["items"]
        app=next(i for i in items if i["kind"]=="Deployment")["spec"]["template"]["spec"]["containers"][0]
        self.assertIn({"name":"MATTERMOST_CA_FILE","value":"/mattermost-ca/ca.pem"},app["env"])
        self.assertTrue(any(i["kind"]=="Secret" and i["metadata"]["name"]=="cvebridge-mattermost-ca" for i in items))


if __name__ == "__main__":
    unittest.main()
