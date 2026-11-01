import importlib.util
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

from app.scheduling import ScheduleError, Scheduler, Schedules, next_due, validate_config

spec = importlib.util.spec_from_file_location("schedule_server", Path(__file__).parents[1]/"app/server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class SchedulingTests(unittest.TestCase):
    channel, alice, bob, bot = "c"*26, "a"*26, "b"*26, "s"*26

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = server.Store(self.directory.name+"/state.db")
        self.schedules = Schedules(self.store)
        self.config = validate_config(list(range(7)), "08:00", "Europe/Stockholm", "scan", ["team-a"])
        self.config["sharingPolicy"] = "requester"

    def save(self, **kwargs):
        return self.schedules.save(self.channel, self.config, True, self.alice, 0, **kwargs)

    def test_local_times_are_converted_to_utc(self):
        self.assertEqual(next_due(self.config, timestamp("2026-10-31T06:00:00Z")), timestamp("2026-10-31T07:00:00Z"))
        self.assertEqual(next_due(self.config, timestamp("2026-06-01T05:00:00Z")), timestamp("2026-06-01T06:00:00Z"))

    def test_nonexistent_spring_time_is_skipped_and_fall_time_runs_once(self):
        config = validate_config([6], "02:30", "Europe/Stockholm", "scan", ["team-a"])
        self.assertEqual(next_due(config, timestamp("2027-03-27T23:00:00Z")), timestamp("2027-04-04T00:30:00Z"))
        self.assertEqual(next_due(config, timestamp("2026-10-25T00:00:00Z")), timestamp("2026-10-25T00:30:00Z"))
        self.assertEqual(next_due(config, timestamp("2026-10-25T00:30:00Z")), timestamp("2026-11-01T01:30:00Z"))

    def test_frequency_timezone_and_days_are_bounded(self):
        for days,times,zone in [([],"08:00","UTC"), ([7],"08:00","UTC"), ([0],"8:00","UTC"),
            ([0],"08:00,08:30","UTC"),([0],"00:00,06:00,12:00,18:00,22:00","UTC"),([0],"08:00","bad/zone")]:
            with self.assertRaises(ScheduleError):
                validate_config(days,times,zone,"scan",["team-a"])

    def test_settings_persist_and_revision_prevents_overwriting_a_team_edit(self):
        self.save()
        second = Schedules(server.Store(self.directory.name+"/state.db"))
        config = self.config | {"times":["08:00","16:00"]}
        second.save(self.channel, config, True, self.bob, 1)
        self.assertEqual(self.schedules.get(self.channel)["config"]["times"], ["08:00","16:00"])
        with self.assertRaises(ScheduleError):
            self.schedules.save(self.channel, self.config, True, self.alice, 1)

    def test_due_slot_is_claimed_once_and_next_run_is_advanced(self):
        self.save(now=timestamp("2026-10-31T06:59:00Z"))
        now = timestamp("2026-10-31T07:00:05Z")
        self.schedules.claim_due(now)
        self.schedules.claim_due(now+1)
        self.assertEqual(len(self.schedules.history(self.channel)), 1)
        self.assertEqual(self.schedules.get(self.channel)["next_due"], timestamp("2026-11-01T07:00:00Z"))

    def test_downtime_records_a_missed_slot_without_a_scan_storm(self):
        self.save(now=timestamp("2026-10-31T06:59:00Z"))
        self.schedules.claim_due(timestamp("2026-11-02T12:00:00Z"))
        self.assertEqual(self.schedules.history(self.channel)[0]["state"], "missed")
        self.assertIsNone(self.schedules.queued())

    def test_pause_cancels_queued_runs_and_blocks_new_manual_run(self):
        self.save()
        self.schedules.enqueue_now(self.channel, 1)
        self.schedules.save(self.channel,self.config,False,self.bob,1)
        self.assertEqual(self.schedules.history(self.channel)[0]["state"], "cancelled")
        with self.assertRaises(ScheduleError):
            self.schedules.enqueue_now(self.channel,2)

    def test_test_runs_are_rate_limited_even_after_editing_the_schedule(self):
        self.save()
        self.schedules.enqueue_now(self.channel,1)
        self.schedules.save(self.channel,self.config,True,self.bob,1)
        with self.assertRaises(ScheduleError):
            self.schedules.enqueue_now(self.channel,2)

    def worker(self):
        services = MagicMock()
        services.scheduled_audience.return_value = {"namespaces":["team-a"], "members":[self.bot,self.alice], "policy":"requester"}
        services.scheduled_scanner.return_value = services
        services.scan.return_value = {"rows":[], "namespaces":["team-a"], "scannedImages":1, "failedImages":0,"unscannedImages":0}
        services.upload_report.return_value = ["f"*26]
        services.send_callback.return_value = {"id":"p"*26}
        runner = MagicMock()
        runner.lock = threading.Lock()
        engine = Scheduler(services,self.schedules,runner)
        self.save()
        self.schedules.enqueue_now(self.channel,1)
        run = self.schedules.queued()
        self.schedules.start(run["id"])
        runner.lock.acquire()
        return engine,services,run

    def test_automatic_run_uses_service_scanner_and_posts_to_approved_channel(self):
        engine,services,run = self.worker()
        engine.execute(run)
        services.scheduled_scanner.assert_called_once()
        self.assertTrue(services.scan.call_args.kwargs["force"])
        self.assertEqual(services.send_callback.call_args.kwargs["channel_id"],self.channel)
        self.assertTrue(services.send_callback.call_args.args[1]["scheduled"])
        self.assertEqual(self.schedules.history(self.channel)[0]["state"],"done")

    def test_report_mode_does_not_force_a_new_scan(self):
        self.config["mode"] = "report"
        engine,services,run = self.worker()
        engine.execute(run)
        self.assertFalse(services.scan.call_args.kwargs["force"])

    def test_changing_membership_during_scan_prevents_upload_and_post(self):
        engine,services,run = self.worker()
        old = services.scheduled_audience.return_value
        services.scheduled_audience.side_effect = [old, old | {"members":[self.bot,self.alice,self.bob]}]
        engine.execute(run)
        services.upload_report.assert_not_called()
        services.send_callback.assert_not_called()
        self.assertEqual(self.schedules.history(self.channel)[0]["state"],"failed")

    def test_pausing_during_scan_prevents_publication(self):
        engine,services,run = self.worker()
        def pause(*args,**kwargs):
            self.schedules.save(self.channel,self.config,False,self.bob,1)
            return {"rows":[],"namespaces":["team-a"],"scannedImages":1,"failedImages":0,"unscannedImages":0}
        services.scan.side_effect = pause
        engine.execute(run)
        services.send_callback.assert_not_called()
        self.assertEqual(self.schedules.history(self.channel)[0]["state"],"failed")

    def test_scanner_outage_sends_failure_notice_without_finding_data(self):
        engine,services,run = self.worker()
        services.scan.side_effect = server.Problem(502,"Scanner unavailable")
        engine.execute(run)
        payload = services.send_callback.call_args.args[1]
        self.assertEqual(payload["kind"],"schedule_error")
        self.assertNotIn("rows",payload)
        self.assertEqual(self.schedules.history(self.channel)[0]["state"],"failed")

    def test_restart_marks_inflight_run_interrupted_without_replaying_it(self):
        engine,services,run = self.worker()
        engine.runner.lock.release()
        Scheduler(services,self.schedules,engine.runner)
        self.assertEqual(self.schedules.history(self.channel)[0]["state"],"interrupted")
        self.assertIsNone(self.schedules.queued())

    def request(self, fields=None, origin="http://localhost:18080"):
        request_id = self.store.create("alice@demo.local","schedule","","/hooks/commands/abc",self.channel,self.alice,shared=True)
        handler = object.__new__(server.Handler)
        handler.store,handler.schedules,handler.scheduler = self.store,self.schedules,MagicMock()
        handler.path = "/requests/"+request_id+"/schedule"
        handler.services = MagicMock()
        handler.services.public = origin
        handler.services.allowed_namespaces.return_value = ["team-a"]
        handler.services.shared_audience.return_value = {"namespaces":["team-a"],"members":[self.alice,self.bot],"policy":"requester"}
        handler.services.scheduled_audience.return_value = handler.services.shared_audience.return_value
        handler.services.schedule_scopes = {self.channel:["team-a"]}
        handler.services.schedule_managers = {}
        body = {"csrf":server.hashlib.sha256(("schedule:"+request_id).encode()).hexdigest(),"revision":"0",
                "days":["0","1"],"times":"08:00","timezone":"Europe/Stockholm","mode":"scan","namespaces":["team-a"],"enabled":"yes","action":"save"}
        body.update(fields or {})
        raw = urlencode(body,doseq=True).encode()
        handler.headers = {"Origin":origin,"X-Forwarded-Email":"alice@demo.local","Content-Length":str(len(raw))}
        handler.rfile = io.BytesIO(raw)
        handler.reply = MagicMock()
        return handler

    def test_browser_requires_csrf_and_matching_origin(self):
        handler = self.request({"csrf":"forged"})
        with self.assertRaises(server.Problem):
            handler.schedule_post()
        handler = self.request()
        handler.headers["Origin"] = "https://attacker.invalid"
        with self.assertRaises(server.Problem):
            handler.schedule_post()
        self.assertIsNone(self.schedules.get(self.channel))

    def test_configuration_cannot_add_an_unapproved_namespace(self):
        handler = self.request({"namespaces":["team-b"]})
        with self.assertRaises(server.Problem):
            handler.schedule_post()
        self.assertIsNone(self.schedules.get(self.channel))

    def test_configuration_is_saved_only_by_the_authenticated_command_owner(self):
        handler = self.request()
        handler.headers["X-Forwarded-Email"] = "bob@demo.local"
        with self.assertRaises(server.Problem):
            handler.schedule_post()
        self.assertIsNone(self.schedules.get(self.channel))

    def test_authorized_configuration_is_persisted_and_posts_confirmation(self):
        handler = self.request()
        handler.schedule_post()
        self.assertEqual(handler.reply.call_args.args[0],200)
        self.assertTrue(self.schedules.get(self.channel)["enabled"])
        self.assertEqual(handler.services.send_callback.call_args.args[1]["kind"],"schedule")

    def test_form_preserves_verifiable_origin_without_cross_site_referrers(self):
        handler = self.request()
        handler.schedule_form("secret-request", {"channel_id":self.channel,"mm_user_id":self.alice,"shared_requested":1}, "alice@demo.local",[])
        self.assertEqual(handler.reply.call_args.kwargs["headers"]["Referrer-Policy"],"same-origin")

    def test_service_grant_is_checked_again_before_scanning(self):
        services = server.Services()
        services.schedule_scopes = {self.channel:["team-a"]}
        services.channel_scopes = {self.channel:["team-a"]}
        services.schedule_user = "system:serviceaccount:security-tools:acs-reporter"
        services.permitted_namespace = MagicMock(return_value=True)
        services.shared_audience = lambda channel,requester,allowed: {"namespaces":allowed,"members":[self.alice,self.bot],"policy":"requester"}
        self.assertEqual(services.scheduled_audience(self.channel,["team-a"])["namespaces"],["team-a"])
        args = services.permitted_namespace.call_args.args
        self.assertEqual(args[0],services.schedule_user)
        self.assertIn("system:serviceaccounts:security-tools",args[1])
        services.permitted_namespace.return_value = False
        with self.assertRaises(server.Problem):
            services.scheduled_audience(self.channel,["team-a"])

    def test_scheduled_scanner_uses_its_own_token(self):
        with patch.dict(os.environ,{"STACKROX_CLUSTER_ID":"cluster-a", "STACKROX_SCHEDULE_TOKEN":"scheduled-token", "STACKROX_TOKEN":"manual-token"}):
            services = server.Services().scheduled_scanner()
            with patch.object(server,"request_json",return_value={}) as request:
                services.rox_request("/v1/pods?query=Namespace:team-a")
                self.assertEqual(request.call_args.kwargs["headers"]["Authorization"],"Bearer scheduled-token")


if __name__ == "__main__":
    unittest.main()
