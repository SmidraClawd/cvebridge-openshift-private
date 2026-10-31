import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

spec=importlib.util.spec_from_file_location("reporting_server",Path(__file__).parents[1]/"app/server.py")
server=importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def report(*findings, namespaces=None, failed=0):
    rows=[{"imageId":"sha256:"+"a"*64,"namespace":"team-a","deployment":"app",
           "component":"example-package","version":"1.0","fixedBy":"1.1","source":"OS",
           "cve":cve,"cvss":cvss} for cve,cvss in findings]
    return {"kind":"scan","mode":"scan","namespaces":namespaces or ["team-a"],"rows":rows,
        "scannedImages":1,"totalImages":1+failed,"failedImages":failed,"unscannedImages":0,
        "partialImages":0,"pods":2,"components":10,"durationSeconds":3,
        "finishedAt":"2026-10-31T16:00:00Z","database":{"state":"unknown","lastUpdated":None},
        "reportFileIds":["f"*26]}


class ReportingTests(unittest.TestCase):
    def test_verified_command_errors_render_but_invalid_tokens_still_fail(self):
        with patch.dict(os.environ,{"SLASH_TOKEN":"test-command-secret"}):
            for token,status in [("test-command-secret",200),("wrong-token",401)]:
                body=urlencode({"command":"/cve","token":token,"text":"CVE-fel"}).encode()
                handler=object.__new__(server.Handler)
                handler.public_listener=True
                handler.path="/slash/cve"
                handler.headers={"Content-Length":str(len(body))}
                handler.rfile=io.BytesIO(body)
                handler.services=server.Services()
                handler.store=Mock()
                handler.reply=Mock()
                handler.do_POST()
                response_status,response=handler.reply.call_args.args
                self.assertEqual(response_status,status)
                self.assertEqual(response["response_type"],"ephemeral")
                self.assertIn("Förfrågan kunde inte slutföras",json.dumps(response,ensure_ascii=False))
                handler.store.create.assert_not_called()

    def test_large_scan_has_bounded_preview_without_losing_report_rows(self):
        result=report(*[("CVE-2026-"+str(10000+i),10-i%5) for i in range(1000)],
            namespaces=["namespace-"+str(i) for i in range(100)])
        previous=copy.deepcopy(result)
        message=server.scan_message(result,shared=True)
        text=message["attachments"][0]["text"]
        self.assertEqual(result,previous)
        self.assertEqual(text.count("• `CVE-"),3)
        self.assertLess(len(json.dumps(message,ensure_ascii=False)),2200)
        self.assertIn("+97 fler",text)
        self.assertIn("JSON-rapport",text)
        self.assertIn("aktualitet är okänd",text)

    def test_incomplete_zero_finding_report_never_claims_complete_or_clean(self):
        message=server.scan_message(report(failed=1))
        self.assertIn("luckor",message["attachments"][0]["title"])
        self.assertIn("bevisar inte",message["attachments"][0]["text"])
        self.assertIn("misslyckade",message["attachments"][0]["text"])

    def test_inventory_mentions_cannot_ping_a_channel(self):
        result=report(("CVE-2026-12345",10))
        result["rows"][0].update(component="@channel @all @here",fixedBy="@channel")
        raw=json.dumps(server.scan_message(result),ensure_ascii=False)
        self.assertNotIn("@channel",raw)
        self.assertNotIn("@all",raw)
        self.assertIn("＠channel",raw)

    def test_large_cve_search_keeps_highest_risk_and_missing_coverage_visible(self):
        result=report(*[("CVE-2026-12345",i%11) for i in range(100)])
        for i,row in enumerate(result["rows"]): row["deployment"]="app-"+str(i)
        result.pop("kind")
        result.update(cve="CVE-2026-12345",unscannedImages=2)
        message=server.result_message(result)
        self.assertLess(len(json.dumps(message,ensure_ascii=False)),2000)
        self.assertIn("3 av 100",message["attachments"][0]["text"])
        self.assertIn("saknar färdigt",message["attachments"][0]["text"])
        self.assertIn("Kritisk",json.dumps(message,ensure_ascii=False))


class NewCveAlertTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.environment=patch.dict(os.environ,{"CVE_ALERTS_ENABLED":"true","CVE_ALERT_MIN_CVSS":"9","CVE_ALERT_FIRST_REPORT":"false"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.store=server.Store(self.directory.name+"/state.sqlite")
        self.alerts=server.CveAlerts(self.store)
        self.services=SimpleNamespace(cluster_id="cluster-a",mm_request=Mock(return_value={"id":"p"*26}))
        self.channel="c"*26

    def publish(self,result,channel=None):
        self.alerts.publish(self.services,channel or self.channel,result)
        return self.services.mm_request.call_args.args[1]

    def test_baseline_then_new_critical_pings_once_across_restart_and_reappearance(self):
        baseline=self.publish(report(("CVE-2026-10000",10)))
        self.assertNotIn("@channel",baseline["message"])
        self.assertIn("utgångsläge",json.dumps(baseline,ensure_ascii=False))
        new=self.publish(report(("CVE-2026-10000",10),("CVE-2026-10001",9.8),("CVE-2026-10002",5)))
        self.assertEqual(new["message"].count("@channel"),1)
        self.assertEqual(new["props"]["cvebridge_alert_cves"],["CVE-2026-10001"])
        self.assertEqual(new["props"]["cvebridge_new_cves"],["CVE-2026-10001","CVE-2026-10002"])
        self.alerts=server.CveAlerts(server.Store(self.store.path))
        self.assertNotIn("@channel",self.publish(report())["message"])
        returned=self.publish(report(("CVE-2026-10001",10)))
        self.assertNotIn("@channel",returned["message"])

    def test_noncritical_new_findings_remain_in_daily_report_without_mass_ping(self):
        self.publish(report())
        post=self.publish(report(("CVE-2026-10000",8.9)))
        self.assertNotIn("@channel",post["message"])
        self.assertIn("CVE-2026-10000",json.dumps(post))

    def test_channel_cluster_and_new_namespace_baselines_are_independent(self):
        self.publish(report())
        result=report(("CVE-2026-10000",10))
        self.assertNotIn("@channel",self.publish(result,channel="d"*26)["message"])
        self.services.cluster_id="cluster-b"
        self.assertNotIn("@channel",self.publish(result)["message"])
        self.services.cluster_id="cluster-a"
        result=report(("CVE-2026-10001",10),namespaces=["team-b"])
        result["rows"][0]["namespace"]="team-b"
        self.assertNotIn("@channel",self.publish(result)["message"])
        self.assertIn("@channel",self.publish(report(("CVE-2026-10002",10)))["message"])

    def test_failed_publication_does_not_consume_the_first_notification(self):
        self.publish(report())
        self.services.mm_request.side_effect=server.Problem(502,"Service unavailable")
        result=report(("CVE-2026-10000",10))
        with self.assertRaises(server.Problem): self.publish(result)
        self.services.mm_request.side_effect=None
        self.assertIn("@channel",self.publish(result)["message"])

    def test_partial_report_cannot_establish_a_complete_baseline(self):
        self.publish(report(failed=1))
        self.assertTrue(self.alerts.preview(self.channel,"cluster-a",report())["alertBaseline"])
        self.publish(report())
        self.assertFalse(self.alerts.preview(self.channel,"cluster-a",report())["alertBaseline"])

    def test_first_report_ping_and_all_severity_threshold_are_explicit_options(self):
        with patch.dict(os.environ,{"CVE_ALERT_FIRST_REPORT":"true","CVE_ALERT_MIN_CVSS":"0"}):
            self.alerts=server.CveAlerts(self.store)
        result=report(("CVE-2026-10000",3))
        self.assertIn("@channel",self.publish(result)["message"])
        self.assertNotIn("@channel",self.publish(result)["message"])

    def test_private_callbacks_never_use_channel_alerts(self):
        services=server.Services()
        services.alerts=Mock()
        with patch.object(server,"request_json") as request:
            services.send_callback("/hooks/commands/test",report(("CVE-2026-10000",10)))
        services.alerts.publish.assert_not_called()
        self.assertNotIn("@channel",json.dumps(request.call_args.kwargs["payload"]))


if __name__=="__main__": unittest.main()
