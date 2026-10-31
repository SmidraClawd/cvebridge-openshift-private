#!/usr/bin/env python3
"""Attach ACS to an approved private channel in the local lab.

Dry run by default. This grants no Kubernetes access. The default common
policy requires each recipient's Kubernetes access. Requester policy explicitly
approves disclosure to channel members while checking the caller's live access.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("acs_platform", ROOT/"scripts/platform.py")
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def onboard(config, *, apply=False):
    channel_id = config.get("channel_id", "")
    namespaces = config.get("namespaces", [])
    proposed = config.get("identities", {})
    policy = config.get("sharing_policy", "common")
    enable_schedule = config.get("enable_schedule", False)
    schedule_managers = config.get("schedule_managers", [])
    if (not isinstance(enable_schedule, bool) or not isinstance(schedule_managers,list)
            or any(not isinstance(u,str) or not re.fullmatch(r"[a-z0-9]{26}",u) for u in schedule_managers)):
        raise RuntimeError("enable_schedule must be boolean; schedule_managers must contain exact user IDs.")
    if policy not in {"common", "requester"}:
        raise RuntimeError("sharing_policy must be common or requester.")
    if not re.fullmatch(r"[a-z0-9]{26}", channel_id):
        raise RuntimeError("Provide the exact 26-character Mattermost channel ID.")
    if (not isinstance(namespaces, list) or not namespaces or len(namespaces) > 100
            or any(not isinstance(n, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", n) for n in namespaces)):
        raise RuntimeError("Provide a nonempty list of literal namespace names, without wildcards.")
    if not isinstance(proposed, dict) or any(
            not re.fullmatch(r"[a-z0-9]{26}", user_id) or not isinstance(email, str)
            or "@" not in email or len(email) > 256 or any(ord(c) < 32 for c in email)
            for user_id, email in proposed.items()):
        raise RuntimeError("Identities must map stable user IDs to approved OIDC emails.")
    local = platform.LOCAL
    mm = json.loads((local/"mattermost.json").read_text())
    settings = json.loads((local/"settings.json").read_text())
    creds = json.loads((local/"credentials.json").read_text())
    base = settings["mattermost_public_url"]
    _, headers = platform.api(base, "/api/v4/users/login", {"login_id": "labadmin", "password": creds["admin"]})
    admin_token = headers["Token"]
    channel, _ = platform.api(base, "/api/v4/channels/"+channel_id, token=admin_token)
    if channel.get("type") != "P" or channel.get("delete_at", 0):
        raise RuntimeError("ACS sharing requires an active private channel.")
    bot, _ = platform.api(base, "/api/v4/users/me", token=mm["integration_token"])
    if bot.get("id") != mm["bot_user_id"] or bot.get("is_bot") is not True or "system_admin" in bot.get("roles", "").split():
        raise RuntimeError("Configure the dedicated, non-admin ACS bot first.")
    mappings_path = local/"identity-map.json"
    mappings = json.loads(mappings_path.read_text()) if mappings_path.exists() else {}
    mappings.update(proposed)
    member_ids = set()
    for page in range(6):
        members, _ = platform.api(base, f"/api/v4/channels/{channel_id}/members?page={page}&per_page=200", token=admin_token)
        member_ids.update(member["user_id"] for member in members)
        if len(members) < 200:
            break
    else:
        raise RuntimeError("This channel is too large for the local onboarding check.")
    humans = member_ids - {mm["bot_user_id"]}
    if not set(schedule_managers) <= humans:
        raise RuntimeError("Schedule managers must be existing human channel members.")
    if not humans:
        raise RuntimeError("The private channel must contain its development team before onboarding ACS.")
    for namespace in namespaces:
        platform.kube("get", "namespace", namespace, capture=True)
    for user_id in sorted(humans):
        account, _ = platform.api(base, "/api/v4/users/"+user_id, token=admin_token)
        if account.get("delete_at", 0) or account.get("is_bot") or not mappings.get(user_id):
            raise RuntimeError("Every human member needs an active account and an approved identity mapping.")
        kube_user = settings.get("identity_prefix", "") + mappings[user_id].lower()
        if settings.get("identity_header", "X-Forwarded-Email") != "X-Forwarded-Email":
            raise RuntimeError("This local helper uses email identities. Use the company deployment process for other mappings.")
        for namespace in namespaces if policy == "common" else []:
            sar = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": {
                "user": kube_user, "groups": ["system:authenticated"], "resourceAttributes": {
                    "namespace": namespace, "verb": "list", "group": "apps", "resource": "deployments"}}}
            review = json.loads(platform.kube("create", "--raw=/apis/authorization.k8s.io/v1/subjectaccessreviews", "-f", "-", payload=sar, capture=True))
            status = review.get("status", {})
            if status.get("evaluationError") or status.get("allowed") is not True or status.get("denied"):
                raise RuntimeError(f"Onboarding denied: {account['username']} cannot read namespace {namespace}. No namespace grants were changed.")
    print("Approved private channel:", channel["display_name"])
    print("Namespaces:", ", ".join(sorted(set(namespaces))))
    print("Verified human members:", len(humans))
    print("Sharing policy:", policy)
    print("Scheduled runs:", "approved" if enable_schedule else "disabled")
    if policy == "requester":
        print("Channel members are approved to read the caller's findings, even without their own namespace access.")
    if not apply:
        print("Dry run passed. Use --apply to add ACS and enable the channel scope.")
        return
    # Only after a complete preflight does the operator-approved scope change.
    platform.api(base, "/api/v4/channels/"+channel_id+"/members", {"user_id": mm["bot_user_id"]}, token=admin_token)
    settings.setdefault("mattermost_channel_scopes", {})[channel_id] = sorted(set(namespaces))
    settings.setdefault("mattermost_channel_policies", {})[channel_id] = policy
    scopes = settings.setdefault("mattermost_schedule_scopes", {})
    managers = settings.setdefault("mattermost_schedule_managers", {})
    if enable_schedule:
        scopes[channel_id] = sorted(set(namespaces))
        if schedule_managers:
            managers[channel_id] = schedule_managers
        else:
            managers.pop(channel_id, None)
    else:
        scopes.pop(channel_id, None)
        managers.pop(channel_id, None)
    rox = json.loads((local/"stackrox.json").read_text())
    if enable_schedule:
        rox = platform.bootstrap_stackrox(creds, [n for scope in scopes.values() for n in scope])
    platform.apply([platform.integration_secret(mm, rox, mappings)])
    platform.apply(platform.common_manifests(settings))
    platform.kube("-n", settings["namespace"], "rollout", "restart", "deploy/cvebridge")
    platform.kube("-n", settings["namespace"], "rollout", "status", "deploy/cvebridge", "--timeout=300s")
    platform.private_json(local/"settings.json", settings)
    platform.private_json(local/"onboarding"/(channel_id+".json"), {
        "channel_id": channel_id, "namespaces": settings["mattermost_channel_scopes"][channel_id], "sharing_policy": policy, "enable_schedule": enable_schedule,
        "verified_members": sorted(humans), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    print("ACS is ready. Run /cve status, /cve scan, or /cve CVE-2022-40897.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Approved team JSON; see config/team.example.json")
    parser.add_argument("--apply", action="store_true", help="Add ACS and deploy the approved scope after preflight")
    args = parser.parse_args()
    try:
        onboard(json.loads(Path(args.config).read_text()), apply=args.apply)
    except (RuntimeError, ValueError, OSError) as exc:
        print("ACS onboarding stopped:", exc, file=sys.stderr)
        sys.exit(1)
