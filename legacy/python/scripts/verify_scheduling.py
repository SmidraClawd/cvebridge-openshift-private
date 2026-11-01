#!/usr/bin/env python3
"""Real Java dependency and wall-clock schedule checks against this local lab.

Creates/edits the demonstration channel's schedule through Mattermost-native
dialogs, observes a real timed delivery, and leaves daily 08:00
Europe/Stockholm scanning enabled for the demo. No clock or database is faked.
"""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import re
import time
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import requests

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("live_checks", ROOT/"scripts/verify.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
LOCAL = ROOT/".local"


def main():
    creds = json.loads((LOCAL/"credentials.json").read_text())
    state = json.loads((LOCAL/"mattermost.json").read_text())
    channel = state["shared_channel_id"]
    report = {"time":datetime.now(timezone.utc).isoformat(),"checks":[]}
    def passed(message):
        report["checks"].append(message)
        print("PASS",message,flush=True)
    mattermost = {}
    for user in ["alice","bob"]:
        session = requests.Session()
        login = session.post("http://localhost:18065/api/v4/users/login",json={"login_id":user,"password":creds[user]},timeout=30)
        login.raise_for_status()
        session.headers["Authorization"] = "Bearer "+login.headers["Token"]
        mattermost[user] = session

    def rows(query, parameters):
        # Inspect this dedicated lab's private state to observe dialog
        # capabilities and execution results; all mutations go through
        # Mattermost's authenticated API, never direct database writes.
        code = "import sqlite3,json,sys; db=sqlite3.connect('/data/requests.sqlite3'); db.row_factory=sqlite3.Row; q,p=json.loads(sys.argv[1]); print(json.dumps([dict(r) for r in db.execute(q,p)]))"
        return json.loads(checks.platform.kube("-n","cvebridge","exec","deploy/cvebridge","-c","app","--",
            "python","-c",code,json.dumps([query,parameters]),capture=True))

    def panel(user="alice"):
        configs=rows("SELECT * FROM schedules WHERE channel_id=?",[channel])
        config=configs[0] if configs else None
        if config: config["config"]=json.loads(config["config"])
        return {"schedule":config,"runs":rows("SELECT * FROM schedule_runs WHERE channel_id=? ORDER BY created DESC LIMIT 10",[channel])}

    def form(user="alice"):
        response = mattermost[user].post("http://localhost:18065/api/v4/commands/execute",json={"channel_id":channel,"command":"/cve schedule"},timeout=30)
        response.raise_for_status()
        assert "/requests/" not in json.dumps(response.json()),"Scheduling still returned a website link"
        actor=mattermost[user].get("http://localhost:18065/api/v4/users/me",timeout=20).json()["id"]
        dialogs=rows("SELECT * FROM native_dialogs WHERE owner=? AND channel=? ORDER BY created DESC LIMIT 1",[actor,channel])
        assert dialogs,"The native dialog did not open"
        return dialogs[0]

    def submit(form_data, fields, user="alice", expected=200, state_override=None):
        values={"action":"save","days":[str(d) for d in range(7)],"times":"08:00","timezone":"Europe/Stockholm",
                "mode":"scan","namespaces":["demo-team-a"],"enabled":"yes"}
        values.update(fields)
        if values["enabled"]=="": values["enabled"]="no"
        payload={"type":"dialog_submission","callback_id":"cvebridge.schedule","state":state_override or form_data["id"],
            "url":"http://cvebridge-webhook.cvebridge.svc:8001/slash/cve/dialog/"+form_data["id"],
            "channel_id":channel,"submission":values}
        response=mattermost[user].post("http://localhost:18065/api/v4/actions/dialogs/submit",json=payload,timeout=60)
        body=response.json()
        failed=response.status_code>=400 or bool(body.get("error") or body.get("errors"))
        assert failed==(expected!=200),"Unexpected native submission result: "+str(response.status_code)+" "+json.dumps(body)[:300]
        return response

    # Ensure real Sensor inventory contains the running Java workload.
    deadline = time.monotonic()+120
    while True:
        deployments = checks.rox("/v1/deployments?query=Namespace:demo-team-a").get("deployments") or []
        java = next((d for d in deployments if d.get("name") == "java-sample"),None)
        if java:
            break
        assert time.monotonic() < deadline,"Sensor did not discover the Java demo"
        time.sleep(3)
    details = checks.rox("/v1/deployments/"+java["id"])
    image_id = details["containers"][0]["image"]["id"]
    image = checks.rox("/v1/images/"+image_id+"?strip_description=true")
    java_components = [c for c in (image.get("scan") or {}).get("components") or [] if c.get("source") == "JAVA"]
    log4j = next((c for c in java_components if c.get("name") == "log4j" and c.get("version") == "2.14.1"),None)
    assert log4j and any(v.get("cve") == "CVE-2021-44228" for v in log4j.get("vulns") or []),"Real Log4j JAR finding was not detected"
    passed("StackRox identifies Java dependencies inside the running Spring Boot image, including Log4j 2.14.1 / CVE-2021-44228")
    report["java_image_id"] = image_id

    first = form()
    assert "demo-team-a" in json.loads(first["snapshot"])["candidates"]
    before = panel()["schedule"]
    submit(first,{},expected=403,state_override="forged")
    submit(first,{},user="bob",expected=403)
    submit(first,{"namespaces":["cvebridge"]},expected=403)
    assert panel()["schedule"] == before
    passed("The bot opens a native Mattermost dialog without a website; forged state, another owner and unauthorized namespaces are rejected")

    now = datetime.now(ZoneInfo("Europe/Stockholm"))
    target = (now+timedelta(minutes=1)).replace(second=0,microsecond=0)
    if (target-now).total_seconds() < 25:
        target += timedelta(minutes=1)
    slots = sorted([target.strftime("%H:%M"),(target+timedelta(hours=2)).strftime("%H:%M")])
    submit(first,{"times":", ".join(slots)})
    current = panel()["schedule"]
    assert current["config"]["times"] == slots and current["config"]["mode"] == "scan"
    assert current["config"]["namespaces"] == ["demo-team-a"]
    assert current["enabled"] == 1 and abs(current["next_due"]-target.timestamp()) < 1
    passed("The team saves two scans per day in its chosen timezone, with a real upcoming wall-clock execution")

    # A second member may change frequency while preserving already approved team
    # scope, despite not personally having access to Alice's namespace.
    update = form("bob")
    assert json.loads(update["snapshot"])["revision"]==current["revision"]
    duplicate = form("alice")
    submit(update,{"times":target.strftime("%H:%M")},user="bob")
    submit(duplicate,{"times":"08:00,16:00"},expected=409)
    current = panel()["schedule"]
    assert current["config"]["times"] == [target.strftime("%H:%M")]
    passed("Another verified team member can edit the schedule; stale forms cannot overwrite the edit")

    revision = current["revision"]
    print("Waiting for real schedule:",target.isoformat(),flush=True)
    deadline = time.monotonic()+max(0,target.timestamp()-time.time())+180
    while True:
        current_panel = panel()
        runs = [r for r in current_panel["runs"] if r["revision"] == revision] if current_panel["runs"] and "revision" in current_panel["runs"][0] else current_panel["runs"]
        timed = next((r for r in runs if abs(r["due"]-target.timestamp()) < 1),None)
        if timed and timed["state"] in {"done","partial","failed","missed","interrupted"}:
            break
        assert time.monotonic() < deadline,"The timed schedule did not finish"
        time.sleep(3)
    assert timed["state"] in {"done","partial"},"Timed scan failed: "+timed.get("error", "")
    summary = json.loads(timed["result"])
    post_id = summary["post_id"]
    posts = {}
    for user in ["alice","bob"]:
        response = mattermost[user].get("http://localhost:18065/api/v4/posts/"+post_id,timeout=30)
        response.raise_for_status()
        posts[user] = response.json()
    assert posts["alice"]["user_id"] == state["bot_user_id"]
    assert posts["alice"]["props"]["attachments"] == posts["bob"]["props"]["attachments"]
    assert any(a.get("title", "").startswith("Automatisk · ")
               for a in posts["alice"]["props"].get("attachments", []))
    file_id = posts["alice"]["file_ids"][0]
    response = mattermost["bob"].get("http://localhost:18065/api/v4/files/"+file_id,timeout=30)
    response.raise_for_status()
    result = response.json()
    assert result["scheduled"] is True and result["mode"] == "scan"
    assert result["failedImages"] == 0 and result["scannedImages"] >= 2
    assert result["namespaces"] == ["demo-team-a"]
    java_rows = [r for r in result["rows"] if r.get("source") == "JAVA" and r["cve"] == "CVE-2021-44228"]
    assert java_rows and all(r["deployment"] == "java-sample" for r in java_rows)
    for entry in result["scanTimes"]:
        scanned = datetime.fromisoformat(entry["scanTime"].replace("Z","+00:00")).timestamp()
        assert scanned >= target.timestamp()-2,"A scheduled forced scan reused an old timestamp"
    report.update(timed_post_id=post_id,timed_due=target.isoformat(),java_findings=len(java_rows),scannedImages=result["scannedImages"])
    passed("The real timer forces new scans without a human session; ACS publishes Java findings and a complete report readable by both team members")

    pause = form("bob")
    submit(pause,{"enabled":"","times":"08:00"},user="bob")
    assert not panel()["schedule"]["enabled"] and panel()["schedule"]["next_due"] is None
    passed("The team can pause automatic scanning and see its delivery history")

    # The next normal run is daily 08:00 Stockholm after the demo test.
    final = form()
    submit(final,{"times":"08:00","enabled":"yes","namespaces":["demo-team-a","demo-shared"]})
    final_panel = panel()
    assert final_panel["schedule"]["config"]["times"] == ["08:00"]
    assert final_panel["schedule"]["enabled"] == 1
    assert final_panel["schedule"]["config"]["namespaces"] == ["demo-shared","demo-team-a"]
    report["final_schedule"] = final_panel["schedule"]
    checks.platform.private_json(LOCAL/"scheduling-verification.json",report)
    passed("Daily 08:00 Europe/Stockholm scanning is enabled and can be adjusted later with /cve schedule")
    print("Verified",len(report["checks"]),"Java/scheduling checks",flush=True)


if __name__ == "__main__":
    main()
