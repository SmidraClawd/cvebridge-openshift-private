#!/usr/bin/env python3
"""Prepare an OpenShift installation from one private configuration file.

No cluster changes, command registration, or Mattermost posts are performed.
Only --online makes a read-only request to identify the existing bot.
"""
import argparse
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import tarfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cvebridge_platform", ROOT/"scripts/platform.py")
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)
ID = re.compile(r"[a-z0-9]{26}\Z")
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
TOKEN_KEYS = {"MATTERMOST_TOKEN", "MATTERMOST_BOT_ID", "SLASH_TOKEN", "SLASH_ACS_TOKEN",
              "STACKROX_TOKEN", "STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"}
PROXY_KEYS = {"OAUTH2_PROXY_CLIENT_SECRET", "OAUTH2_PROXY_COOKIE_SECRET"}


class ConfigError(Exception):
    pass


def initialize(path):
    data = json.loads((ROOT/"config/company.example.json").read_text())
    data["credentials"].update(OAUTH2_PROXY_CLIENT_SECRET=secrets.token_urlsafe(32),
                              OAUTH2_PROXY_COOKIE_SECRET=base64.b64encode(secrets.token_bytes(32)).decode())
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Never replace an existing file or follow an existing symlink.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def https_url(value, field):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and parsed.path in {"", "/"}
                 and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
                 and not any(c.isspace() for c in value) and "example." not in parsed.hostname
                 and "REPLACE" not in value)
        parsed.port  # Validate a malformed/out-of-range port without echoing it.
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ConfigError(field+": ange en HTTPS-basadress utan sökväg eller inloggningsuppgifter.")
    return value.rstrip("/")


def ca_bundle(data, base, field):
    value = data.get(field, "")
    if not isinstance(value, str):
        raise ConfigError(field+": ange en PEM-fil eller en tom sträng för systemets CA-certifikat.")
    if value:
        try:
            pem = (base/value).read_text()
            ssl.create_default_context(cadata=pem)
            return pem
        except (OSError, ValueError, ssl.SSLError):
            raise ConfigError(field+": kunde inte läsa en giltig CA-kedja i PEM-format.") from None
    context = ssl.create_default_context()
    return "".join(ssl.DER_cert_to_PEM_cert(cert) for cert in context.get_ca_certs(binary_form=True))


def resolve_bot(data, base):
    """Discover the immutable bot ID without relying on its editable name."""
    settings, creds = data.get("settings", {}), data.get("credentials", {})
    url = https_url(settings.get("mattermost_internal_url"), "mattermost_internal_url")
    token = creds.get("MATTERMOST_TOKEN")
    if not isinstance(token, str) or not token or any(c.isspace() for c in token):
        raise ConfigError("credentials.MATTERMOST_TOKEN: fyll i botens access-token.")
    try:
        context = ssl.create_default_context(cadata=ca_bundle(data, base, "mattermost_ca_file"))
        request = Request(url+"/api/v4/users/me", headers={"Authorization":"Bearer "+token, "Accept":"application/json"})
        with urlopen(request, context=context, timeout=15) as response:
            bot = json.loads(response.read(1024*1024))
    except Exception:
        raise ConfigError("Mattermost: botkontrollen misslyckades; kontrollera adress, TLS och token.") from None
    if (not isinstance(bot, dict) or bot.get("is_bot") is not True
            or "system_admin" in bot.get("roles", "").split() or not ID.fullmatch(bot.get("id", ""))):
        raise ConfigError("Mattermost: token måste tillhöra ett vanligt botkonto utan system-admin.")
    if creds.get("MATTERMOST_BOT_ID") and creds["MATTERMOST_BOT_ID"] != bot["id"]:
        raise ConfigError("MATTERMOST_BOT_ID: stämmer inte med botens token.")
    creds["MATTERMOST_BOT_ID"] = bot["id"]


def validate(data, base):
    if not isinstance(data, dict) or not isinstance(data.get("settings"), dict) or not isinstance(data.get("credentials"), dict):
        raise ConfigError("Konfigurationen måste innehålla objekten settings och credentials.")
    data = copy.deepcopy(data)
    settings, creds = data["settings"], data["credentials"]
    if settings.get("auth_provider") != "openshift":
        raise ConfigError("settings.auth_provider: företagsstarten använder openshift.")
    if not NAME.fullmatch(settings.get("namespace", "")):
        raise ConfigError("settings.namespace: ange ett giltigt projektnamn.")
    if settings.get("node_port"):
        raise ConfigError("settings.node_port: företagsstarten använder HTTPS Routes.")
    for field in ["public_url", "mattermost_public_url", "mattermost_internal_url", "stackrox_url"]:
        settings[field] = https_url(settings.get(field), "settings."+field)
    # Route hosts cannot include a custom port. An empty webhook URL means
    # Mattermost will use the in-cluster Service instead of an external Route.
    for field in ["public_url", "webhook_public_url"]:
        if settings.get(field):
            settings[field] = https_url(settings[field], "settings."+field)
            if urlsplit(settings[field]).port:
                raise ConfigError("settings."+field+": Route-adressen ska sakna portnummer.")
    for field in ["app_image", "openshift_proxy_image"]:
        image = settings.get(field, "")
        if not isinstance(image, str) or not image or "REPLACE" in image or any(c.isspace() for c in image):
            raise ConfigError("settings."+field+": ange en publicerad image med godkänd version eller digest.")
    if not re.fullmatch(r"[a-zA-Z0-9-]+", settings.get("stackrox_cluster_id", "")) or "REPLACE" in settings["stackrox_cluster_id"]:
        raise ConfigError("settings.stackrox_cluster_id: ange exakt ID för det anslutna klustret i ACS.")
    required = {"MATTERMOST_TOKEN", "STACKROX_TOKEN", "STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN"}
    if settings.get("mattermost_schedule_scopes"):
        required.add("STACKROX_SCHEDULE_TOKEN")
    for key in required | PROXY_KEYS:
        value = creds.get(key)
        if not isinstance(value, str) or not value or "REPLACE" in value or any(c.isspace() for c in value):
            raise ConfigError("credentials."+key+": fyll i ett giltigt värde.")
    if not ID.fullmatch(creds.get("MATTERMOST_BOT_ID", "")):
        raise ConfigError("credentials.MATTERMOST_BOT_ID: fyll i botens ID eller använd --online för att läsa det.")
    slash_tokens = [creds.get(key) for key in ["SLASH_TOKEN", "SLASH_ACS_TOKEN"] if creds.get(key)]
    if (not slash_tokens or any(not isinstance(t, str) or any(c.isspace() for c in t) for t in slash_tokens)
            or len(set(slash_tokens+[creds["MATTERMOST_TOKEN"]])) != len(slash_tokens)+1):
        raise ConfigError("credentials.SLASH_TOKEN/SLASH_ACS_TOKEN: ange minst en unik kommando-token, skild från botens token.")
    try:
        if len(base64.b64decode(creds["OAUTH2_PROXY_COOKIE_SECRET"], validate=True)) != 32:
            raise ValueError()
    except ValueError:
        raise ConfigError("credentials.OAUTH2_PROXY_COOKIE_SECRET: måste vara 32 slumpbyte i base64.") from None
    users = creds.get("MATTERMOST_KUBE_USER_MAP")
    if (not isinstance(users, dict) or not users or any(not ID.fullmatch(k) or not isinstance(v, str)
            or not v or len(v)>256 or v.startswith("system:") or any(ord(c)<32 for c in v) for k,v in users.items())):
        raise ConfigError("credentials.MATTERMOST_KUBE_USER_MAP: koppla stabila Mattermost-ID:n till exakta OpenShift-användarnamn.")
    scopes = settings.get("mattermost_channel_scopes", {})
    if (not isinstance(scopes, dict) or any(not ID.fullmatch(k) or not isinstance(v, list) or not 1<=len(v)<=100
            or any(not isinstance(n,str) or not NAME.fullmatch(n) for n in v) for k,v in scopes.items())):
        raise ConfigError("settings.mattermost_channel_scopes: ange kanal-ID:n och godkända namespace-listor.")
    policies = settings.get("mattermost_channel_policies", {})
    schedules = settings.get("mattermost_schedule_scopes", {})
    managers = settings.get("mattermost_schedule_managers", {})
    if not isinstance(policies, dict) or any(k not in scopes or v not in {"common", "requester"} for k,v in policies.items()):
        raise ConfigError("settings.mattermost_channel_policies: välj common eller requester för en godkänd kanal.")
    if not isinstance(schedules,dict) or any(k not in scopes or not isinstance(v,list) or not v
            or any(not isinstance(n,str) or n not in scopes[k] for n in v) for k,v in schedules.items()):
        raise ConfigError("settings.mattermost_schedule_scopes: måste vara en delmängd av kanalens godkända namespaces.")
    if not isinstance(managers,dict) or any(k not in schedules or not isinstance(v,list) or not v
            or any(not isinstance(u,str) or u not in users for u in v) for k,v in managers.items()):
        raise ConfigError("settings.mattermost_schedule_managers: ange verifierade användare för en schemagodkänd kanal.")
    try:
        ZoneInfo(settings.get("schedule_default_timezone", "Europe/Stockholm"))
        if not 0 < float(settings.get("database_max_age_hours",24)) <= 8760:
            raise ValueError()
    except (ZoneInfoNotFoundError, TypeError, ValueError):
        raise ConfigError("settings: kontrollera tidszon och databasens tillåtna ålder.") from None
    if settings.get("stackrox_scanner_component", "SCANNER_V4") not in {"SCANNER", "SCANNER_V4"}:
        raise ConfigError("settings.stackrox_scanner_component: välj SCANNER eller SCANNER_V4.")
    if not isinstance(settings.get("stackrox_delegate_scan",False),bool):
        raise ConfigError("settings.stackrox_delegate_scan: välj true eller false.")
    for key in ["cve_alerts_enabled", "cve_alert_first_report"]:
        if not isinstance(settings.get(key, key=="cve_alerts_enabled"), bool):
            raise ConfigError("settings."+key+": välj true eller false.")
    try:
        if not 0 <= float(settings.get("cve_alert_min_cvss",9)) <= 10:
            raise ValueError()
    except (ValueError,TypeError):
        raise ConfigError("settings.cve_alert_min_cvss: välj ett tal mellan 0 och 10.") from None
    client_id = settings.setdefault("openshift_oauth_client_id", "cvebridge-"+settings["namespace"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", client_id):
        raise ConfigError("settings.openshift_oauth_client_id: ange ett giltigt klientnamn.")
    ca_bundle(data, base, "stackrox_ca_file")
    ca_bundle(data, base, "mattermost_ca_file")
    return data


def installation(data, base):
    data = validate(data, base)
    settings, creds = data["settings"], data["credentials"]
    settings["mattermost_custom_ca"] = bool(data.get("mattermost_ca_file"))
    items = platform.common_manifests(settings)
    integration = {k:v for k,v in creds.items() if k in TOKEN_KEYS and v}
    integration["MATTERMOST_KUBE_USER_MAP"] = json.dumps(creds["MATTERMOST_KUBE_USER_MAP"])
    inputs = [platform.secret("cvebridge-integration", integration),
              platform.secret("cvebridge-proxy", {k:creds[k] for k in PROXY_KEYS}),
              platform.secret("cvebridge-rox-ca", {"ca.pem":ca_bundle(data,base,"stackrox_ca_file")})]
    if settings["mattermost_custom_ca"]:
        inputs.append(platform.secret("cvebridge-mattermost-ca", {"ca.pem":ca_bundle(data,base,"mattermost_ca_file")}))
    client = {"apiVersion":"oauth.openshift.io/v1", "kind":"OAuthClient",
              "metadata":{"name":settings["openshift_oauth_client_id"]},
              "secret":creds["OAUTH2_PROXY_CLIENT_SECRET"], "grantMethod":"prompt",
              "redirectURIs":[settings["public_url"]+"/oauth2/callback"],
              "scopeRestrictions":[{"literals":["user:info"]}]}
    return {"apiVersion":"v1", "kind":"List", "items":[items[0], *inputs, client, *items[1:]]}


def prepare(data, base, output):
    manifest = installation(data, base)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    platform.private_json(output/"install.json", manifest)
    # Review file deliberately excludes Secrets and the secret-bearing OAuthClient.
    platform.private_json(output/"deployment.json", {**manifest, "items":[i for i in manifest["items"] if i["kind"] not in {"Secret","OAuthClient"}]})
    # An allowlist prevents accidentally sending .local credentials to a builder.
    path = output/"app-source.tar.gz"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd,"wb") as stream, tarfile.open(fileobj=stream, mode="w:gz") as archive:
        archive.add(ROOT/"app/Dockerfile", arcname="Dockerfile")
        for name in ["__init__.py", "server.py", "scheduling.py"]:
            archive.add(ROOT/"app"/name, arcname="app/"+name)
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=["init","check","prepare"])
    parser.add_argument("--file",type=Path,default=ROOT/".local/company.json")
    parser.add_argument("--output",type=Path,default=ROOT/".local/company-install")
    parser.add_argument("--online",action="store_true",help="Läs botens ID via Mattermost; inga ändringar skickas.")
    args = parser.parse_args()
    try:
        if args.action == "init":
            initialize(args.file)
            print("Privat konfigurationsfil skapad. Fyll i företagets värden lokalt: "+str(args.file))
            return
        data = json.loads(args.file.read_text())
        if args.online:
            resolve_bot(data,args.file.parent)
        data = validate(data,args.file.parent)
        if args.action == "prepare":
            prepare(data,args.file.parent,args.output)
            print("Installationsfiler skapade i "+str(args.output)+". install.json innehåller hemligheter. Inget har installerats.")
        else:
            print("Konfigurationen är giltig."+(" Botens identitet har kontrollerats." if args.online else " Ingen nätverkskontroll har gjorts."))
    except (ConfigError, OSError, ValueError, TypeError, KeyError) as exc:
        # JSON/parser/OS exception text can contain credential fragments or paths.
        print(str(exc) if isinstance(exc,ConfigError) else "Kunde inte läsa eller skriva konfigurationen. Kontrollera filformat, sökväg och behörighet.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
