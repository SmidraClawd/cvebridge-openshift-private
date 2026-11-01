#!/usr/bin/env python3
"""End-to-end checks against the installed, real services; no fixture CVE data."""
import argparse
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("platform_install", ROOT/"scripts/platform.py")
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)
LOCAL = ROOT/".local"


class Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = ""
        self.inputs = {}
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action", "")
        if tag == "input" and attrs.get("name"):
            self.inputs[attrs["name"]] = attrs.get("value", "")


def anonymous_get(url, **kwargs):
    # A pod can be ready just before the NodePort rules have converged.
    # Retry only connection failures; authorization status codes are tested as-is.
    for attempt in range(10):
        try:
            return requests.get(url, **kwargs)
        except (requests.ConnectionError, requests.Timeout):
            if attempt == 9:
                raise
            time.sleep(1)


def login_browser(user, password):
    session = requests.Session()
    response = session.get("http://localhost:18080/", timeout=30)
    if response.status_code != 200:
        raise AssertionError("OIDC login page did not load: "+str(response.status_code))
    form = Form()
    form.feed(response.text)
    if "login" not in form.inputs or "password" not in form.inputs:
        raise AssertionError("Dex password form was not reached")
    data = form.inputs | {"login": user+"@demo.local", "password": password}
    response = session.post(urljoin(response.url, form.action), data=data, timeout=60)
    if urlsplit(response.url).path == "/dex/approval":
        # Approve only this lab's already configured client and test identity.
        # Some IdP policies still require explicit first-use consent.
        approval = Form()
        approval.feed(response.text)
        response = session.post(urljoin(response.url, approval.action), data=approval.inputs | {"approval": "approve"}, timeout=60)
    assert response.status_code == 200, "OIDC login failed: "+str(response.status_code)
    if "Sårbarheter i dina miljöer" not in response.text:
        failed = LOCAL/"failed-login.html"
        failed.write_text(response.text)
        failed.chmod(0o600)
        raise AssertionError("Proxy did not establish the browser session; final path="+urlsplit(response.url).path+" (private diagnostic: .local/failed-login.html)")
    assert user+"@demo.local" in response.text
    return session, response


class CentralAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        # NodePort is localhost; verify the certificate's actual service DNS
        # name and its CA rather than disabling TLS certificate verification.
        kwargs["assert_hostname"] = "central.stackrox.svc"
        return super().init_poolmanager(connections, maxsize, block=block, **kwargs)


def rox(path):
    state = json.loads((LOCAL/"stackrox.json").read_text())
    session = requests.Session()
    session.mount("https://localhost:18443", CentralAdapter())
    response = session.get("https://localhost:18443"+path, headers={"Authorization": "Bearer "+state["token"]},
                           verify=str(LOCAL/"central-ca.pem"), timeout=45)
    if response.status_code == 404 and path.startswith("/v1/images/"):
        return {}  # inventory can arrive before the first image scan
    response.raise_for_status()
    return response.json()


def scanned_cve(wait_seconds):
    deadline = time.monotonic()+wait_seconds
    while True:
        deployments = rox("/v1/deployments?query=Namespace:demo-team-a").get("deployments") or []
        for deployment in deployments:
            if deployment.get("namespace") != "demo-team-a":
                continue
            details = rox("/v1/deployments/"+deployment["id"])
            for container in details.get("containers") or []:
                image_id = (container.get("image") or {}).get("id")
                if not image_id:
                    continue
                image = rox("/v1/images/"+image_id+"?strip_description=true")
                for component in (image.get("scan") or {}).get("components") or []:
                    for vuln in component.get("vulns") or []:
                        if re.fullmatch(r"CVE-\d{4}-\d{4,19}", vuln.get("cve", "")):
                            return vuln["cve"]
        if time.monotonic() >= deadline:
            raise AssertionError("No real sample-image CVE is available yet. Inspect StackRox Scanner status; no mock data was substituted.")
        print("Waiting for StackRox to finish the first real sample-image scan...", flush=True)
        time.sleep(20)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-wait", type=int, default=1800)
    args = parser.parse_args()
    report = {"checks": [], "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    def passed(name):
        report["checks"].append(name)
        print("PASS", name, flush=True)
    creds = json.loads((LOCAL/"credentials.json").read_text())
    state = json.loads((LOCAL/"mattermost.json").read_text())
    for path in ["/", "/search?cve=CVE-2023-0286"]:
        response = anonymous_get("http://localhost:18080"+path, headers={"X-Forwarded-Email": "alice@demo.local", "X-Forwarded-User": "alice"}, allow_redirects=False, timeout=20)
        assert response.status_code in [302, 303], "Spoofed identity bypassed the proxy"
    passed("Anonymous and forged identity headers cannot bypass the proxy")
    sessions = {}
    for user, allowed, forbidden in [("alice", "demo-team-a", "demo-team-b"), ("bob", "demo-team-b", "demo-team-a")]:
        session, response = login_browser(user, creds[user])
        assert allowed in response.text and forbidden not in response.text
        response = session.get("http://localhost:18080/search", params={"cve": "CVE-2023-0286", "namespace": forbidden}, timeout=60)
        assert response.status_code == 403
        sessions[user] = session
        passed(user+" sees only their namespace; cross-team access is denied")
    response = sessions["bob"].get("http://localhost:18080/", headers={"X-Forwarded-Email": "alice@demo.local", "X-Forwarded-Groups": "system:masters"}, timeout=60)
    assert response.status_code == 200 and "demo-team-b" in response.text and "demo-team-a" not in response.text
    passed("An authenticated user cannot replace their identity with forwarded headers")
    response = sessions["alice"].get("http://localhost:18080/search", params={"cve": "CVE-2024-1234+Namespace:demo-team-b"}, timeout=30)
    assert response.status_code == 400
    passed("CVE search injection is rejected")
    response = sessions["alice"].get("http://localhost:18080/search", params={"cve": "CVE-2099-9999999"}, timeout=180)
    assert response.status_code == 200
    assert "ej färdigskannade" in response.text and "inte ett bevis" in response.text
    assert "demo-team-b" not in response.text
    passed("A no-match lookup reports scan coverage without claiming the environment is safe")
    cve = scanned_cve(args.scan_wait)
    report["example_cve"] = cve
    passed("StackRox scanned the real sample image and returned "+cve)
    for user in ["alice", "bob"]:
        response = sessions[user].get("http://localhost:18080/search", params={"cve": cve}, timeout=180)
        assert response.status_code == 200, "CVE lookup failed: "+str(response.status_code)
        assert "sample-app" in response.text, "Real positive CVE result was not rendered"
        assert ("demo-team-b" if user == "alice" else "demo-team-a") not in response.text
    passed("Real positive CVE results remain scoped to the authenticated team")
    mm = requests.Session()
    response = mm.post("http://localhost:18065/api/v4/users/login", json={"login_id": "alice", "password": creds["alice"]}, timeout=30)
    response.raise_for_status()
    mm.headers["Authorization"] = "Bearer "+response.headers["Token"]
    channels = mm.get("http://localhost:18065/api/v4/users/me/teams/"+state["team_id"]+"/channels", timeout=30).json()
    channel = next(c for c in channels if c["name"] == "town-square")
    response = mm.post("http://localhost:18065/api/v4/commands/execute", json={"channel_id": channel["id"], "command": "/cve "+cve}, timeout=30)
    response.raise_for_status()
    payload = response.json()
    assert payload.get("username") == "ACS", "Command responses must be branded ACS, not the developer"
    link = re.search(r"http://localhost:18080/requests/[A-Za-z0-9_-]+", json.dumps(payload))
    assert link, "The real Mattermost slash command did not return a login link"
    link = link.group(0)
    passed("Mattermost executes the registered /cve slash command")
    assert anonymous_get(link, allow_redirects=False, timeout=30).status_code in [302, 303]
    assert sessions["bob"].get(link, timeout=60).status_code == 403
    passed("Slash-command links require login and cannot be used by another account")
    response = sessions["alice"].get(link, timeout=180)
    assert response.status_code == 200
    assert "skickats privat till Mattermost" in response.text
    assert "sample-app" in response.text
    assert "demo-team-b" not in response.text
    passed("Authenticated lookup sends a real ephemeral response back to Mattermost")
    assert sessions["alice"].get(link, timeout=30).status_code == 404
    passed("Delivered command links cannot be replayed")
    response = mm.post("http://localhost:18065/api/v4/commands/execute", json={"channel_id": channel["id"], "command": "/acs help"}, timeout=30)
    response.raise_for_status()
    assert response.json().get("username") == "ACS" and "StackRox skannar" in json.dumps(response.json(),ensure_ascii=False)
    passed("ACS help explains team onboarding and distinguishes scanning from CVE lookup")
    shared_channel = state["shared_channel_id"]
    def posts(client):
        response = client.get("http://localhost:18065/api/v4/channels/"+shared_channel+"/posts", timeout=30)
        response.raise_for_status()
        return response.json()
    def shared_link(namespace=""):
        response = mm.post("http://localhost:18065/api/v4/commands/execute",
                           json={"channel_id": shared_channel, "command": "/acs "+cve+(" "+namespace if namespace else "")}, timeout=30)
        response.raise_for_status()
        match = re.search(r"http://localhost:18080/requests/[A-Za-z0-9_-]+", json.dumps(response.json()))
        assert match, "Shared-channel command did not return a private login link"
        return match.group(0)
    before = set(posts(mm)["order"])
    shared_url = shared_link()
    assert sessions["bob"].get(shared_url, timeout=60).status_code == 403
    response = sessions["alice"].get(shared_url, timeout=180)
    assert response.status_code == 200, "Shared lookup failed: "+str(response.status_code)
    assert "delats i Mattermost-kanalen" in response.text and "demo-shared" in response.text
    assert "demo-team-a" in response.text and "demo-team-b" not in response.text
    after = posts(mm)
    new_posts = [after["posts"][post_id] for post_id in set(after["order"])-before]
    result_posts = [p for p in new_posts if cve in p["message"] and "beställarens godkända" in p["message"]]
    assert len(result_posts) == 1, "Expected one persisted, shared CVE result"
    shared_post = result_posts[0]
    assert shared_post["user_id"] == state["bot_user_id"], "Shared result was attributed to the requesting developer"
    author = mm.get("http://localhost:18065/api/v4/users/"+shared_post["user_id"], timeout=30).json()
    assert author.get("is_bot") is True and author["username"] == "acs"
    assert "system_admin" not in author["roles"].split()
    attachments = shared_post.get("props", {}).get("attachments") or []
    assert attachments and attachments[0].get("fields"), "Structured ACS result card was not persisted"
    shared_text = json.dumps(shared_post, ensure_ascii=False)
    assert "demo-shared/sample-app" in shared_text
    assert "demo-team-a" in shared_text and "demo-team-b" not in shared_text
    passed("A real non-admin ACS bot authors formatted result cards instead of Alice")
    mm_bob = requests.Session()
    response = mm_bob.post("http://localhost:18065/api/v4/users/login", json={"login_id": "bob", "password": creds["bob"]}, timeout=30)
    response.raise_for_status()
    mm_bob.headers["Authorization"] = "Bearer "+response.headers["Token"]
    assert posts(mm_bob)["posts"][shared_post["id"]]["message"] == shared_post["message"]
    assert posts(mm_bob)["posts"][shared_post["id"]]["props"]["attachments"] == attachments
    passed("Bob can read Alice's authorized findings through the explicitly approved requester-sharing channel")
    before = set(posts(mm)["order"])
    response = sessions["alice"].get(shared_link("demo-team-b"), timeout=90)
    assert response.status_code == 403
    assert set(posts(mm)["order"]) == before, "A personal namespace was posted to the group"
    passed("The requester cannot scan or share another developer's unauthorized namespace")

    def run_command(command, user="alice", client=None, channel_id=shared_channel):
        client = client or mm
        reply = client.post("http://localhost:18065/api/v4/commands/execute", json={"channel_id": channel_id, "command": command}, timeout=30)
        reply.raise_for_status()
        match = re.search(r"http://localhost:18080/requests/[A-Za-z0-9_-]+", json.dumps(reply.json()))
        assert match, command+" did not return an authenticated command link"
        assert sessions["bob" if user == "alice" else "alice"].get(match.group(0), timeout=30).status_code == 403
        response = sessions[user].get(match.group(0), timeout=180)
        assert response.status_code == 200, command+" failed: "+str(response.status_code)
        return response

    before = set(posts(mm)["order"])
    run_command("/cve status")
    new_posts = [p for k,p in posts(mm)["posts"].items() if k not in before]
    status_post = next(p for p in new_posts if "CVE-databas" in p["message"])
    database = requests.Session()
    database.mount("https://localhost:18443", CentralAdapter())
    rox_state = json.loads((LOCAL/"stackrox.json").read_text())
    data = database.get("https://localhost:18443/v1/integrationhealth/vulndefinitions?component=SCANNER", headers={"Authorization": "Bearer "+rox_state["status_token"]}, verify=str(LOCAL/"central-ca.pem"), timeout=30)
    data.raise_for_status()
    expected_time = datetime.fromisoformat(data.json()["lastUpdatedTimestamp"].replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    assert expected_time in json.dumps(status_post)
    assert status_post["user_id"] == state["bot_user_id"]
    passed("/cve status posts the actual authenticated StackRox definitions timestamp in an ACS card")

    for user, client, expected, forbidden in [("alice", mm, "demo-team-a", "demo-team-b"), ("bob", mm_bob, "demo-team-b", "demo-team-a")]:
        before = set(posts(client)["order"])
        response = run_command("/cve scan", user=user, client=client)
        assert "/jobs/" in response.url, "Scan did not start as a background job"
        job_url = response.url.split("?",1)[0]
        assert sessions["bob" if user == "alice" else "alice"].get(job_url+"?format=json", timeout=30).status_code == 403
        deadline = time.monotonic()+240
        while True:
            job = sessions[user].get(job_url+"?format=json", timeout=60).json()
            if job["state"] != "running":
                break
            assert time.monotonic() < deadline, "Scan job timed out"
            time.sleep(2)
        assert job["state"] == "done", "Scan job failed: "+job.get("error", "")
        result = job["result"]
        assert expected in result["namespaces"] and forbidden not in result["namespaces"]
        assert result["scannedImages"] >= 1 and result["failedImages"] == 0
        assert result["scanTimes"] and result["rows"]
        assert all(r["namespace"] in result["namespaces"] for r in result["rows"])
        scan_posts = [p for k,p in posts(client)["posts"].items() if k not in before and
                      any(a.get("title", "").startswith("Skanning klar") for a in p.get("props",{}).get("attachments",[]))]
        assert len(scan_posts) == 1
        scan_post = scan_posts[0]
        assert scan_post["user_id"] == state["bot_user_id"] and scan_post["props"]["attachments"]
        assert scan_post.get("file_ids"), "Shared scan lacks the complete JSON report"
        other = mm_bob if user == "alice" else mm
        assert posts(other)["posts"][scan_post["id"]]["message"] == scan_post["message"]
        downloaded = other.get("http://localhost:18065/api/v4/files/"+scan_post["file_ids"][0], timeout=30)
        downloaded.raise_for_status()
        assert downloaded.json()["rows"] == result["rows"]
        passed("/cve scan forces real scans for "+user+"; both channel members can read the ACS card and complete report")
        report.setdefault("scan_results", {})[user] = {k:result[k] for k in ["namespaces", "scannedImages", "pods", "components", "finishedAt"]}
        report["scan_results"][user]["post_id"] = scan_post["id"]

    before = set(posts(mm)["order"])
    response = run_command("/cve scan demo-team-a", channel_id=channel["id"])
    deadline = time.monotonic()+240
    while True:
        job = sessions["alice"].get(response.url.split("?",1)[0]+"?format=json", timeout=60).json()
        if job["state"] != "running":
            break
        assert time.monotonic() < deadline, "Private scan timed out"
        time.sleep(2)
    assert job["state"] == "done" and job["result"]["delivery"] == "private"
    assert job["result"]["namespaces"] == ["demo-team-a"]
    assert set(posts(mm)["order"]) == before
    passed("Unapproved channels deliver scan results privately without adding a shared channel post")

    before = set(posts(mm)["order"])
    denied = mm.post("http://localhost:18065/api/v4/commands/execute", json={"channel_id": shared_channel, "command": "/cve scan demo-team-b"}, timeout=30)
    denied.raise_for_status()
    link = re.search(r"http://localhost:18080/requests/[A-Za-z0-9_-]+", json.dumps(denied.json())).group(0)
    assert sessions["alice"].get(link, timeout=60).status_code == 403
    assert set(posts(mm)["order"]) == before
    passed("/cve scan rejects another developer's namespace without publishing findings")
    original = json.loads(platform.kube("-n", "demo-team-a", "get", "rolebinding", "cve-reader", "-o", "json", capture=True))
    try:
        platform.kube("-n", "demo-team-a", "delete", "rolebinding", "cve-reader")
        response = sessions["alice"].get("http://localhost:18080/search", params={"cve": cve, "namespace": "demo-team-a"}, timeout=60)
        assert response.status_code == 403
        passed("Revoking Kubernetes RBAC immediately revokes CVE access")
    finally:
        for key in ["resourceVersion", "uid", "creationTimestamp", "managedFields"]:
            original["metadata"].pop(key, None)
        platform.apply([original])
    platform.private_json(LOCAL/"verification.json", report)
    print("Verified", len(report["checks"]), "checks. Example command: /acs", cve, flush=True)


if __name__ == "__main__":
    main()
