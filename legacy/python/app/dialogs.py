"""Mattermost-native scheduling with short-lived, owner-bound form capabilities.

The slash command authenticates the actor through the Mattermost server. Only
administrator-approved account mappings and live username-based SAR grants are
used; this path never invents the actor's OpenShift/IdP groups.
"""
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from app.scheduling import DAY_NAMES, ScheduleError, validate_config

LOG = logging.getLogger("cvebridge.dialogs")
CALLBACK = "cvebridge.schedule"


class NativeSchedules:
    def __init__(self, services, store, schedules, scheduler):
        self.services, self.store = services, store
        self.schedules, self.scheduler = schedules, scheduler
        with store.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS native_dialogs (id TEXT PRIMARY KEY, created REAL, owner TEXT, channel TEXT, snapshot TEXT, claimed INTEGER NOT NULL DEFAULT 0)")

    def context(self, owner, channel):
        s = self.services
        if channel not in s.schedule_scopes:
            raise ScheduleError(403, "Kanalen är inte godkänd för automatiska körningar.")
        if s.schedule_managers.get(channel) and owner not in s.schedule_managers[channel]:
            raise ScheduleError(403, "Du är inte utsedd att ändra kanalens schema.")
        account = s.expected_user(owner)
        mappings = json.loads(os.getenv("MATTERMOST_KUBE_USER_MAP", "{}"))
        user = mappings.get(owner)
        if s.auth_provider == "openshift":
            if not user or account != "openshift:" + user:
                raise ScheduleError(403, "Kontot saknar en godkänd OpenShift-koppling.")
        elif user is None and os.getenv("IDENTITY_HEADER", "X-Forwarded-Email") == "X-Forwarded-Email":
            user = os.getenv("IDENTITY_PREFIX", "") + account
        if not isinstance(user, str) or not user or user.startswith("system:"):
            raise ScheduleError(403, "Kontot saknar en godkänd Kubernetes-identitet.")
        allowed = [n for n in s.schedule_scopes[channel]
                   if s.permitted_namespace(user, ["system:authenticated"], n)]
        actor = s.shared_audience(channel, owner, allowed)
        audience = s.scheduled_audience(channel, [])
        current = self.schedules.get(channel)
        existing = set(current["config"]["namespaces"]) if current else set()
        candidates = sorted((set(actor["namespaces"]) | existing) & set(audience["namespaces"]))
        if not candidates:
            raise ScheduleError(403, "Inga namespaces är godkända för teamet och rapporttjänsten.")
        return current, {"account": account, "candidates": candidates,
                         "members": audience["members"], "policy": audience["policy"],
                         "revision": current["revision"] if current else 0}

    def callback_base(self):
        value = os.getenv("MATTERMOST_DIALOG_URL", "")
        if not value:
            raise ScheduleError(503, "Formulärets anslutning är inte konfigurerad. Kontakta drift.")
        return value.rstrip("/")

    def open(self, owner, channel, trigger_id):
        if not isinstance(trigger_id, str) or not 1 <= len(trigger_id) <= 512:
            raise ScheduleError(400, "Kör /cve schedule igen för att öppna formuläret.")
        with self.store.connect() as db:
            db.execute("DELETE FROM native_dialogs WHERE created < ?", (time.time()-600,))
            if db.execute("SELECT COUNT(*) FROM native_dialogs WHERE owner=? AND created>?", (owner,time.time()-60)).fetchone()[0] >= 20:
                raise ScheduleError(429, "För många formulär. Vänta en minut.")
        current, snapshot = self.context(owner, channel)
        key = secrets.token_urlsafe(32)
        with self.store.connect() as db:
            db.execute("INSERT INTO native_dialogs (id,created,owner,channel,snapshot) VALUES (?,?,?,?,?)",
                       (key,time.time(),owner,channel,json.dumps(snapshot)))
        config = current["config"] if current else {"days":list(range(7)), "times":["08:00"],
            "timezone":os.getenv("SCHEDULE_DEFAULT_TIMEZONE","Europe/Stockholm"),
            "mode":"scan", "namespaces":snapshot["candidates"]}
        def select(name, label, options, default, multi=False):
            return {"name":name,"display_name":label,"type":"select","options":[{"text":t,"value":v} for v,t in options],
                    "default":default, **({"multiselect":True} if multi else {})}
        actions = [("save","Spara inställningar")]
        if current:
            actions += [("pause","Pausa sparat schema"),("run","Provkör sparat schema"),("history","Visa körhistorik")]
        dialog = {"callback_id":CALLBACK,"title":"Teamets schema","state":key,
            "introduction_text":"Välj dagar, tider och namespaces. Spara för att börja köra automatiskt.",
            "submit_label":"Utför","notify_on_cancel":True,"elements":[
                select("days","Veckodagar",[(str(i),d) for i,d in enumerate(DAY_NAMES)],",".join(map(str,config["days"])),True),
                {"name":"times","display_name":"Tider","type":"text","default":", ".join(config["times"]),"help_text":"Exempel: 08:00, 15:00. Högst fyra tider, minst en timme mellan."},
                {"name":"timezone","display_name":"Tidszon","type":"text","default":config["timezone"],"help_text":"Exempel: Europe/Stockholm"},
                select("namespaces","Namespaces",[(n,n) for n in snapshot["candidates"]],",".join(config["namespaces"]),True),
                select("mode","Vad ska göras?",[("scan","Ny skanning och rapport"),("report","Rapport från befintliga fynd")],config["mode"]),
                select("enabled","Efter sparning",[("yes","Aktiverat"),("no","Pausat")],"yes" if not current or current["enabled"] else "no"),
                select("action","Åtgärd",actions,"save")
            ]}
        try:
            self.services.mm_request("/api/v4/actions/dialogs/open", {"trigger_id":trigger_id,
                "url":self.callback_base()+"/"+key,"dialog":dialog})
        except Exception:
            with self.store.connect() as db:
                db.execute("DELETE FROM native_dialogs WHERE id=?", (key,))
            raise
        return dialog

    def notice(self, owner, channel, text):
        try:
            self.services.mm_request("/api/v4/posts/ephemeral", {"user_id":owner,
                "post":{"channel_id":channel,"message":text}})
        except Exception:
            LOG.warning("dialog_receipt_not_delivered")

    @staticmethod
    def multiple(value):
        if isinstance(value, str):
            value = value.split(",") if value else []
        if not isinstance(value, list) or any(not isinstance(v,str) for v in value):
            raise ScheduleError(400, "Välj giltiga dagar och namespaces.")
        return value

    def submit(self, key, payload):
        if not isinstance(payload, dict):
            raise ScheduleError(400, "Formuläret kunde inte läsas.")
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM native_dialogs WHERE id=? AND created>?", (key,time.time()-600)).fetchone()
        if not row:
            raise ScheduleError(404, "Formuläret har gått ut. Kör /cve schedule igen.")
        if (payload.get("type")!="dialog_submission" or payload.get("callback_id")!=CALLBACK
                or not isinstance(payload.get("state"),str) or not hmac.compare_digest(payload["state"],key)
                or payload.get("user_id")!=row["owner"] or payload.get("channel_id")!=row["channel"]):
            raise ScheduleError(403, "Formulärets avsändare eller kanal kunde inte verifieras.")
        with self.store.connect() as db:
            claimed = db.execute("UPDATE native_dialogs SET claimed=1 WHERE id=? AND claimed=0", (key,)).rowcount
        if not claimed:
            raise ScheduleError(409, "Formuläret behandlas redan. Kontrollera kanalens bekräftelse.")
        completed = False
        try:
            if payload.get("cancelled") is True:
                completed = True
                return {}
            current, fresh = self.context(row["owner"],row["channel"])
            saved = json.loads(row["snapshot"])
            if any(fresh[k]!=saved[k] for k in ["account","members","policy"]):
                raise ScheduleError(403, "Identitet eller kanalbehörigheter ändrades. Kör /cve schedule igen.")
            if fresh["revision"]!=saved["revision"]:
                raise ScheduleError(409, "Schemat ändrades. Öppna /cve schedule igen.")
            form = payload.get("submission")
            if not isinstance(form,dict):
                raise ScheduleError(400, "Formuläret kunde inte läsas.")
            action = form.get("action")
            if action == "save":
                for name in ["times","timezone","mode","enabled"]:
                    if not isinstance(form.get(name),str) or len(form[name])>256:
                        raise ScheduleError(400, "Kontrollera formulärets fält.")
                if form["enabled"] not in {"yes","no"}:
                    raise ScheduleError(400, "Välj aktiverat eller pausat.")
                config = validate_config(self.multiple(form.get("days")),form["times"],form["timezone"],
                                         form["mode"],self.multiple(form.get("namespaces")))
                if not set(config["namespaces"]) <= (set(fresh["candidates"]) & set(saved["candidates"])):
                    raise ScheduleError(403, "Valda namespaces är inte godkända för denna beställning.")
                config["sharingPolicy"] = fresh["policy"]
                result = self.schedules.save(row["channel"],config,form["enabled"]=="yes",row["owner"],saved["revision"])
                completed = True
                self.confirm(row["owner"],row["channel"],result)
            elif action == "pause" and current:
                result = self.schedules.save(row["channel"],current["config"],False,row["owner"],saved["revision"])
                completed = True
                self.confirm(row["owner"],row["channel"],result)
            elif action == "run" and current:
                self.services.scheduled_audience(row["channel"],current["config"]["namespaces"])
                self.schedules.enqueue_now(row["channel"],saved["revision"])
                completed = True
                self.scheduler.tick()
                self.notice(row["owner"],row["channel"],"**ACS · Provkörning köad**\nDet sparade schemat används. Rapporten kommer i kanalen när körningen är klar.")
            elif action == "history" and current:
                names={"queued":"Väntar","running":"Pågår","done":"Levererad","partial":"Levererad med luckor","failed":"Misslyckad","missed":"Missad","cancelled":"Avbruten","interrupted":"Avbruten vid omstart"}
                lines=["**ACS · Senaste körningar**"]
                for run in self.schedules.history(row["channel"])[:5]:
                    stamp=datetime.fromtimestamp(run["due"],timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    lines.append("• "+stamp+" · "+names.get(run["state"],"Okänd"))
                self.notice(row["owner"],row["channel"],"\n".join(lines) if len(lines)>1 else lines[0]+"\nInga körningar ännu.")
                completed = True
            else:
                raise ScheduleError(400, "Välj en giltig åtgärd. Spara ett schema före provkörning.")
            return {}
        finally:
            with self.store.connect() as db:
                if completed:
                    db.execute("DELETE FROM native_dialogs WHERE id=?", (key,))
                else:
                    db.execute("UPDATE native_dialogs SET claimed=0 WHERE id=?", (key,))

    def confirm(self, owner, channel, result):
        try:
            self.services.send_callback("",{"kind":"schedule",**result},shared=True,channel_id=channel)
        except Exception:
            LOG.warning("dialog_channel_confirmation_not_delivered")
            self.notice(owner,channel,"**ACS · Schemat är sparat**\nKanalbekräftelsen kunde inte skickas. Kör /cve schedule för att se inställningarna.")
