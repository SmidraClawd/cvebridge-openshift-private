import io
import json
import os
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode
from app.server import Handler, Problem, Services, Store
from app.scheduling import ScheduleError, Schedules
from app.dialogs import NativeSchedules, CALLBACK


class NativeScheduleTests(unittest.TestCase):
    owner, other, channel, bot = "a"*26, "b"*26, "c"*26, "s"*26

    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.store = Store(directory.name+"/state.db"); self.schedules = Schedules(self.store)
        env=patch.dict(os.environ,{"MATTERMOST_DIALOG_URL":"https://acs.example.test/slash/cve/dialog",
            "MATTERMOST_KUBE_USER_MAP":"{}","IDENTITY_HEADER":"X-Forwarded-Email","IDENTITY_PREFIX":""})
        env.start(); self.addCleanup(env.stop)
        self.services=Services(); self.services.schedule_scopes={self.channel:["team-a","team-b"]}
        self.services.schedule_managers={}; self.services.expected_user=Mock(return_value="alice@demo.local")
        self.services.permitted_namespace=Mock(side_effect=lambda user,groups,n:n=="team-a")
        def actor(channel,owner,allowed):
            if not allowed: raise Problem(403,"Ingen behörighet")
            return {"namespaces":allowed,"members":[self.owner,self.bot],"policy":"requester"}
        self.services.shared_audience=Mock(side_effect=actor)
        self.services.scheduled_audience=Mock(return_value={"namespaces":["team-a","team-b"],"members":[self.owner,self.bot],"policy":"requester"})
        self.services.mm_request=Mock(return_value={}); self.services.send_callback=Mock()
        self.scheduler=Mock(); self.native=NativeSchedules(self.services,self.store,self.schedules,self.scheduler)

    def form(self):
        dialog=self.native.open(self.owner,self.channel,"valid-trigger")
        return dialog["state"]

    def submit(self,key,**fields):
        payload={"type":"dialog_submission","callback_id":CALLBACK,"state":key,"user_id":self.owner,
            "channel_id":self.channel,"submission":{"action":"save","days":["0","1","2","3","4"],
            "times":"08:00, 15:00","timezone":"Europe/Stockholm","mode":"scan","namespaces":["team-a"],"enabled":"yes"}}
        payload["submission"].update(fields)
        return self.native.submit(key,payload)

    def test_form_uses_only_approved_namespaces_and_saves_without_browser_login(self):
        key=self.form(); request=self.services.mm_request.call_args.args[1]
        self.assertEqual(request["dialog"]["title"],"Teamets schema")
        namespaces=next(e for e in request["dialog"]["elements"] if e["name"]=="namespaces")
        self.assertEqual(namespaces["options"],[{"text":"team-a","value":"team-a"}])
        self.submit(key)
        saved=self.schedules.get(self.channel)
        self.assertEqual(saved["config"]["times"],["08:00","15:00"])
        self.assertEqual(saved["config"]["namespaces"],["team-a"])
        self.services.send_callback.assert_called_once()
        self.services.permitted_namespace.assert_any_call("alice@demo.local",["system:authenticated"],"team-a")

    def test_wrong_actor_channel_state_or_callback_is_rejected(self):
        for field,value in [("user_id",self.other),("channel_id","d"*26),("state","wrong"),("callback_id","other")]:
            key=self.form(); payload={"type":"dialog_submission","callback_id":CALLBACK,"state":key,
                "user_id":self.owner,"channel_id":self.channel,"submission":{}}
            payload[field]=value
            with self.assertRaises(ScheduleError) as error: self.native.submit(key,payload)
            self.assertEqual(error.exception.status,403)
        self.assertIsNone(self.schedules.get(self.channel))

    def test_expiry_replay_and_concurrent_submission_cannot_mutate_twice(self):
        key=self.form()
        with self.store.connect() as db: db.execute("UPDATE native_dialogs SET created=? WHERE id=?",(time.time()-601,key))
        with self.assertRaises(ScheduleError): self.submit(key)
        key=self.form()
        with self.store.connect() as db: db.execute("UPDATE native_dialogs SET claimed=1 WHERE id=?",(key,))
        with self.assertRaises(ScheduleError): self.submit(key)
        self.assertIsNone(self.schedules.get(self.channel))
        key=self.form(); self.submit(key)
        with self.assertRaises(ScheduleError): self.submit(key)
        self.assertEqual(self.schedules.get(self.channel)["revision"],1)

    def test_invalid_times_can_be_corrected_without_losing_the_form(self):
        key=self.form()
        with self.assertRaises(ScheduleError): self.submit(key,times="08:00,08:10")
        self.assertIsNone(self.schedules.get(self.channel)); self.submit(key)

    def test_namespace_injection_and_revoked_access_are_denied(self):
        key=self.form()
        with self.assertRaises(ScheduleError): self.submit(key,namespaces=["team-b"])
        self.services.permitted_namespace.side_effect=lambda *a:False
        with self.assertRaises(Problem): self.submit(key)
        self.assertIsNone(self.schedules.get(self.channel))

    def test_changed_audience_or_identity_prevents_saving(self):
        key=self.form(); self.services.scheduled_audience.return_value["members"].append(self.other)
        with self.assertRaises(ScheduleError): self.submit(key)
        self.assertIsNone(self.schedules.get(self.channel))
        key=self.form(); self.services.expected_user.return_value="another@demo.local"
        with self.assertRaises(ScheduleError): self.submit(key)

    def test_stale_form_cannot_overwrite_a_team_edit(self):
        first,second=self.form(),self.form(); self.submit(first)
        with self.assertRaises(ScheduleError) as error: self.submit(second,times="09:00")
        self.assertEqual(error.exception.status,409)
        self.assertEqual(self.schedules.get(self.channel)["config"]["times"],["08:00","15:00"])

    def test_pause_and_test_use_saved_config_and_history_is_private(self):
        self.submit(self.form()); self.submit(self.form(),action="run",times="22:00")
        self.assertEqual(self.schedules.get(self.channel)["config"]["times"],["08:00","15:00"])
        self.scheduler.tick.assert_called_once()
        self.submit(self.form(),action="history")
        path,notice=self.services.mm_request.call_args.args
        self.assertEqual(path,"/api/v4/posts/ephemeral"); self.assertEqual(notice["user_id"],self.owner)
        self.submit(self.form(),action="pause"); self.assertFalse(self.schedules.get(self.channel)["enabled"])

    def test_only_designated_managers_can_open_or_submit(self):
        key=self.form(); self.services.schedule_managers={self.channel:[self.other]}
        with self.assertRaises(ScheduleError): self.native.open(self.owner,self.channel,"trigger")
        with self.assertRaises(ScheduleError): self.submit(key)

    def test_openshift_needs_exact_admin_mapping_without_claiming_sso_groups(self):
        self.services.auth_provider="openshift"; self.services.expected_user.return_value="openshift:Alice"
        with self.assertRaises(ScheduleError): self.form()
        with patch.dict(os.environ,{"MATTERMOST_KUBE_USER_MAP":json.dumps({self.owner:"Alice"})}):
            self.submit(self.form())
        self.services.permitted_namespace.assert_any_call("Alice",["system:authenticated"],"team-a")

    def test_cancel_does_not_save_and_failed_receipt_does_not_undo_success(self):
        key=self.form(); self.native.submit(key,{"type":"dialog_submission","callback_id":CALLBACK,"state":key,
            "user_id":self.owner,"channel_id":self.channel,"cancelled":True})
        self.assertIsNone(self.schedules.get(self.channel))
        self.services.send_callback.side_effect=Problem(502,"Unavailable")
        key=self.form(); self.submit(key)
        self.assertIsNotNone(self.schedules.get(self.channel))
        with self.assertRaises(ScheduleError): self.submit(key)

    def test_slash_command_opens_dialog_without_creating_a_web_link(self):
        body=urlencode({"command":"/cve","token":"correct","text":"schedule","user_id":self.owner,
            "channel_id":self.channel,"trigger_id":"valid-trigger","response_url":"http://localhost:18065/hooks/commands/abc"}).encode()
        h=object.__new__(Handler); h.path="/slash/cve"; h.public_listener=True
        h.headers={"Content-Length":str(len(body))}; h.rfile=io.BytesIO(body)
        h.services=self.services; h.store=self.store; h.native_schedules=self.native; h.reply=Mock()
        with patch.dict(os.environ,{"SLASH_TOKEN":"correct"}): h.do_POST()
        status,reply=h.reply.call_args.args; self.assertEqual(status,200)
        self.assertNotIn("/requests/",json.dumps(reply)); self.assertIn("Mattermost",reply["text"])


if __name__ == "__main__": unittest.main()
