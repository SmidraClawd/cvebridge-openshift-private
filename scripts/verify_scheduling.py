#!/usr/bin/env python3
"""Real Java dependency and wall-clock schedule checks against this local lab.

Creates/edits the demonstration channel's schedule through its authenticated
configuration form, observes a real timed delivery, and leaves daily 08:00
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
    browsers, mattermost = {}, {}
    for user in ["alice","bob"]:
        browsers[user], _ = checks.login_browser(user,creds[user])
        session = requests.Session()
        login = session.post("http://localhost:18065/api/v4/users/login",json={"login_id":user,"password":creds[user]},timeout=30)
        login.raise_for_status()
        session.headers["Authorization"] = "Bearer "+login.headers["Token"]
        mattermost[user] = session

    def panel(user="alice"):
        response = browsers[user].get("http://localhost:18080/schedules/"+channel+"?format=json",timeout=30)
        response.raise_for_status()
        return response.json()

    def form(user="alice"):
        response = mattermost[user].post("http://localhost:18065/api/v4/commands/execute",json={"channel_id":channel,"command":"/cve schedule"},timeout=30)
        response.raise_for_status()
        match = re.search(r"http://localhost:18080/requests/[A-Za-z0-9_-]+",json.dumps(response.json()))
        assert match,"Schedule command did not return a private owner-bound link"
        url = match.group(0)
        assert browsers["bob" if user == "alice" else "alice"].get(url,timeout=30).status_code == 403
        page = browsers[user].get(url,timeout=30)
        assert page.status_code == 200,"Configuration page failed: "+str(page.status_code)
        parsed = checks.Form()
        parsed.feed(page.text)
        return urljoin(url,parsed.action),parsed.inputs,page.text

    def submit(form_data, fields, user="alice", expected=200, origin="http://localhost:18080"):
        url,inputs,_ = form_data
        payload = {"csrf":inputs["csrf"],"revision":inputs["revision"],"action":"save","days":[str(d) for d in range(7)],
                   "times":"08:00","timezone":"Europe/Stockholm","mode":"scan","namespaces":["demo-team-a"],"enabled":"yes"}
        payload.update(fields)
        response = browsers[user].post(url,data=payload,headers={"Origin":origin},timeout=60)
        assert response.status_code == expected,"Configuration submit returned "+str(response.status_code)
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
    assert "Tider" in first[2] and "Europe/Stockholm" in first[2] and "Spara schema" in first[2]
    before = panel()["schedule"]
    submit(first,{"csrf":"forged"},expected=403)
    submit(first,{},expected=403,origin="https://attacker.invalid")
    submit(first,{"namespaces":["cvebridge"]},expected=403)
    assert panel()["schedule"] == before
    passed("The bot opens an authenticated first-configuration form; wrong owner, CSRF, foreign origins and unauthorized namespaces are rejected")

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
    assert target.strftime("%H:%M") in update[2]
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
