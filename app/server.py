"""CVE Bridge: authenticated CVE lookup using real Kubernetes SAR and StackRox APIs.

The browser listener binds ONLY to loopback inside the proxy's pod. The separately
exposed webhook listener never accepts browser identity headers as authentication.
"""
import base64
from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import Request, urlopen
from app.scheduling import DAY_NAMES, ScheduleError, Scheduler, Schedules, validate_config
from app.dialogs import NativeSchedules

LOG = logging.getLogger("cvebridge")
CVE = re.compile(r"CVE-\d{4}-\d{4,19}\Z")
NS = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class Problem(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def request_json(url, *, payload=None, headers=None, context=None, method=None, expect_json=True, timeout=30):
    body = None if payload is None else json.dumps(payload).encode()
    hdrs = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        with urlopen(Request(url, data=body, headers=hdrs, method=method),
                     context=context, timeout=timeout) as response:
            data = response.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024:
                raise Problem(502, "Svaret från tjänsten är för stort. Avgränsa till ett namespace.")
            if not expect_json:
                return {}  # Mattermost command callbacks acknowledge with plain 'ok'.
            return json.loads(data) if data else {}
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        # Never include upstream URLs, credentials, or response bodies in errors.
        LOG.warning("upstream_failure type=%s status=%s", type(exc).__name__, getattr(exc, "code", "network"))
        raise Problem(502, "En nödvändig tjänst kan inte nås. Inga fynd lämnades ut.") from exc


def validate_cve(value):
    value = value.strip().upper()
    if not CVE.fullmatch(value):
        raise Problem(400, "Ange ett giltigt CVE-nummer, till exempel CVE-2023-0286.")
    return value


def validate_namespace(value):
    if value and not NS.fullmatch(value):
        raise Problem(400, "Ogiltigt namespace. Kontrollera namnet och försök igen.")
    return value


def verify_command_token(expected, authorization, form_token):
    candidates = []
    if authorization:
        parts = authorization.strip().split(None, 1)
        # Mattermost 12 uses 'Token'; other supported clients use 'Bearer'.
        if len(parts) != 2 or parts[0].lower() not in {"token", "bearer"}:
            raise Problem(401, "Kommandot kunde inte verifieras. Be drift kontrollera integrationen.")
        candidates.append(parts[1])
    if form_token:
        candidates.append(form_token)
    if not expected or not candidates or any(not hmac.compare_digest(value.encode(), expected.encode()) for value in candidates):
        raise Problem(401, "Kommandot kunde inte verifieras. Be drift kontrollera integrationen.")


def inert(value, limit=100):
    text = " ".join(str(value).replace("`", "").replace("@", "＠").replace("|", "/").split())
    if len(text) > limit:
        text = text[:limit-1]+"…"
    return "`"+html.escape(text)+"`"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def readable_time(stamp):
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError, AttributeError):
        return "Ej verifierad"


def score(row):
    try:
        value = float(row.get("cvss") or 0)
        return value if 0 <= value <= 10 else 0
    except (TypeError, ValueError):
        return 0


def risk(value):
    return (("Kritisk", "#D64550") if value >= 9 else ("Hög", "#D97732") if value >= 7 else
            ("Medel", "#C89431") if value >= 4 else ("Låg", "#438D9A") if value > 0 else ("Ej bedömd", "#718096"))


def scope_text(namespaces):
    names = sorted(set(namespaces))
    return " · ".join(inert(n,64) for n in names[:3])+(f" · +{len(names)-3} fler" if len(names)>3 else "") or "Ej angivet"


def card_message(title, text, *, summary="", fields=None, color="#438D9A", footer="ACS · StackRox"):
    card = {"fallback":title+(" · "+summary if summary else ""), "title":title, "text":text,
            "color":color, "footer":footer}
    if fields:
        card["fields"] = fields
    return {"text":summary, "attachments":[card]}


def field(title, value, short=True):
    return {"title":title,"value":str(value),"short":short}


def result_message(result, *, shared=False):
    """Bounded summaries; the full scan data stays in the report attachment."""
    kind = result.get("kind")
    if kind == "status":
        return status_message(result, shared=shared)
    if kind == "scan":
        return scan_message(result, shared=shared)
    if kind == "schedule":
        return schedule_message(result)
    if kind == "schedule_error":
        return card_message("Automatisk körning misslyckades",
            "Rapporten kunde inte bekräftas levererad. Kör `/cve schedule` och läs körhistoriken.",
            summary="**ACS · Körningen behöver kontrolleras**",color="#D64550",
            footer="ACS · "+readable_time(result["checkedAt"]))
    rows = result["rows"]
    highest = max((score(row) for row in rows), default=0)
    label,color = risk(highest)
    audience = ("beställarens godkända namespaces" if result.get("sharingPolicy")=="requester" else
                "kanalens gemensamt tillåtna namespaces") if shared else "dina tillåtna namespaces"
    details = []
    # Combine repeated workload/package rows, retaining their complete raw data.
    groups = {}
    for row in rows:
        key = (row["namespace"],row["deployment"],row["component"],row["version"],row.get("fixedBy", ""))
        groups.setdefault(key,row)
    displayed = sorted(groups.values(), key=lambda row:(-score(row),row["namespace"],row["deployment"],row["component"]))[:3]
    for row in displayed:
        details.append("• "+inert(row["namespace"]+"/"+row["deployment"],80)+"\n  "+inert(row["component"],45)+" "+
                       inert(row["version"],24)+" → "+inert(row.get("fixedBy") or "ingen fix angiven",24))
    if len(groups)>3:
        details.append(f"Visar 3 av {len(groups)} berörda paket/arbetslaster. Avgränsa med ett namespace eller sök i webbappen.")
    if not rows:
        details.append("Inga matchande fynd i tillgängliga skanningar. Ett tomt resultat bevisar inte att miljön är fri från sårbarheter.")
    missing = result.get("unscannedImages",0)
    if missing:
        details.append(f"⚠ {missing} containerbilder saknar färdigt skanningsunderlag.")
    details.append("**Namespace:** "+scope_text(result.get("namespaces",[])))
    if rows:
        details.append("**Åtgärd:** uppdatera berörda paket, bygg om och rulla ut containerbilderna. Kontrollera med en ny skanning.")
    return card_message("Berörda arbetslaster", "\n".join(details),
        summary=f"**{result['cve']}** · {len(rows)} fynd i {audience}", color=color,
        fields=[field("Högsta risk", label+(f" · CVSS {highest:g}" if highest else "")),
                field("Underlag",f"{result['scannedImages']} skannade · {missing} saknas")],
        footer="ACS · "+("Delat i kanalen" if shared else "Privat resultat"))


def status_message(result, *, shared=False):
    state = result["state"]
    title,color = {"recent":("Databasen är nyligen uppdaterad","#329C89"),
                   "stale":("Databasen behöver uppdateras","#D97732"),
                   "unknown":("Databasens aktualitet är okänd","#718096")}[state]
    age = result.get("ageHours")
    age_text = (f"{age/24:.1f} dygn" if age is not None and age>=48 else f"{age:.1f} timmar") if age is not None else "Okänd"
    text = ("Be plattformsteamet kontrollera uppdateringen." if state=="stale" else
            "Kontrollera anslutningen och läsbehörigheten." if state=="unknown" else "Uppdaterad inom den valda tidsgränsen.")
    text += "\nEn ny imageskanning innebär inte att CVE-databasen har uppdaterats."
    return card_message(title,text,summary="**ACS · CVE-databas**",color=color,
        fields=[field("Ålder / gräns",age_text+" / "+str(result["maxAgeHours"])+" timmar"),
                field("Senast uppdaterad",readable_time(result.get("lastUpdated")))],
        footer="ACS · "+str(result["component"])+" · "+readable_time(result["checkedAt"]))


def scan_message(result, *, shared=False):
    rows = result["rows"]
    unique = {}
    for row in rows:
        unique[(row["imageId"],row["component"],row["version"],row["cve"])] = row
    counts = {"Kritisk":0,"Hög":0,"Medel":0,"Låg":0,"Ej bedömd":0}
    for row in unique.values():
        counts[risk(score(row))[0]] += 1
    incomplete = result["failedImages"] or result["unscannedImages"] or result.get("partialImages") or result.get("truncated")
    reporting = result.get("mode")=="report"
    title = "Rapport klar" if reporting else "Skanning klar"
    if result.get("scheduled"):
        title = "Automatisk · "+title.lower()
    if incomplete:
        title += " med luckor"
    highest = max((score(row) for row in rows),default=0)
    color = risk(highest)[1] if rows else "#438D9A"
    if incomplete and highest<7:
        color="#D97732"
    details = ["**Namespace:** "+scope_text(result["namespaces"]),
               "**Paketfynd per risk:** "+" · ".join(f"{k} {v}" for k,v in counts.items() if v)]
    if not rows:
        details[1]="Inga fynd i tillgängligt underlag. Ett tomt resultat bevisar inte att miljön är fri från sårbarheter."
    # Highest score first; each CVE appears once in the compact preview.
    urgent = set(result.get("alertCves",[]))
    ranked = sorted(unique.values(),key=lambda row:(row["cve"] not in urgent,-score(row),row["cve"],row["component"]))
    top = []
    shown = set()
    for row in ranked:
        if row["cve"] in shown:
            continue
        shown.add(row["cve"])
        top.append(row)
        if len(top)==3:
            break
    if top:
        details.append("\n**Prioriterade fynd**")
        for row in top:
            details.append("• "+inert(row["cve"],30)+f" · {score(row):g} · "+inert(row["component"],38)+
                           (" · fix i underlaget "+inert(row["fixedBy"],22) if row.get("fixedBy") else
                            " · ingen fix angiven."))
        details.append("\n**Åtgärd:** välj aktuell säker paketversion, bygg om och rulla ut. Skanna igen.")
    if incomplete:
        gaps=[]
        for count,label in [(result["failedImages"],"misslyckade"),(result["unscannedImages"],"saknar underlag"),(result.get("partialImages",0),"med varningar")]:
            if count:
                gaps.append(str(count)+" "+label)
        if result.get("truncated"):
            gaps.append("rapportgränsen uppnådd")
        details.append("⚠ **Luckor:** "+" · ".join(gaps)+".")
        translations={"OS_UNAVAILABLE":"operativsystem ej identifierat","OS_CVES_UNAVAILABLE":"OS-sårbarheter saknas",
            "OS_CVES_STALE":"gammalt OS-underlag","LANGUAGE_CVES_UNAVAILABLE":"språkpaketens sårbarheter saknas",
            "PARTIAL_SCAN_DATA":"delvis skanningsdata","CERTIFIED_RHEL_SCAN_UNAVAILABLE":"certifierad RHEL-skanning saknas"}
        notes=sorted({n for w in result.get("warnings",[]) for n in w.get("scanNotes",[])})
        if notes:
            details.append("⚠ "+" · ".join(translations.get(n,inert(n,45)) for n in notes[:2])+(" · fler varningar i rapporten" if len(notes)>2 else ""))
    db=result["database"]
    if db["state"]=="stale":
        details.append("⚠ **CVE-databasen är gammal** · "+readable_time(db.get("lastUpdated")))
    elif db["state"]=="unknown":
        details.append("⚠ **CVE-databasens aktualitet är okänd.**")
    if result.get("reportFileIds"):
        details.append("**Alla fynd och detaljer:** bifogad JSON-rapport.")
    elif result.get("reportUrl"):
        details.append("[Öppna min fullständiga rapport]("+result["reportUrl"]+") · inloggning krävs")
    if "newCves" in result:
        details.insert(1, ("**Bevakning:** första rapporten skapar ett utgångsläge." if result.get("alertBaseline") else
                          f"**Nytt för kanalen:** {len(result['newCves'])} CVE:er · {len(result.get('alertCves',[]))} över larmgränsen."))
    summary=f"**{len({r['cve'] for r in rows})} CVE:er** · {len(unique)} paketfynd"
    details.insert(1,f"**Täckning:** {result['scannedImages']}/{result['totalImages']} bilder · {result['pods']} poddar · {result['components']} paket")
    return card_message(title,"\n".join(details),summary=summary,color=color,
        footer="ACS · "+("Befintligt underlag" if reporting else "Ny imageskanning")+" · "+readable_time(result["finishedAt"])+f" · {result['durationSeconds']} s")


def schedule_message(result):
    config=result["config"]
    enabled=bool(result["enabled"])
    days=config["days"]
    day_text="Varje dag" if days==list(range(7)) else "Mån–fre" if days==list(range(5)) else ", ".join(DAY_NAMES[d][:3] for d in days)
    due=readable_time(datetime.fromtimestamp(result["next_due"],timezone.utc).isoformat()) if result.get("next_due") else "Ingen körning planerad"
    title="Automatiska körningar aktiverade" if enabled else "Automatiska körningar pausade"
    return card_message(title,"**Namespace:** "+scope_text(config["namespaces"])+"\nKör `/cve schedule` för att ändra, provköra eller pausa.",
        summary="**ACS · Teamets schema**",color="#329C89" if enabled else "#718096",
        fields=[field("När",day_text+" · "+", ".join(config["times"])+"\n"+config["timezone"]),
                field("Nästa körning",due)],
        footer="ACS · "+("Ny skanning och rapport" if config["mode"]=="scan" else "Rapport från befintliga skanningar")+" · Revision "+str(result["revision"]))


def help_message():
    return card_message("Vad vill du göra?","StackRox skannar; ACS beställer och visar rapporten.\nSchema ställs in direkt i Mattermost. Skanning och CVE-sökning använder en privat inloggningslänk.",
        summary="**ACS · Snabbhjälp**",fields=[
            field("Skanna nu","`/cve scan [namespace]`\nNy skanning och rapport."),
            field("Sök en CVE","`/cve CVE-2021-44228 [namespace]`\nSök i befintliga fynd."),
            field("Automatisera","`/cve schedule`\nÖppna formuläret här i Mattermost."),
            field("Databasstatus","`/cve status`\nSe när underlaget uppdaterades.")],footer="ACS · /acs fungerar också")


def request_message(link, cve, namespace, shared, policy):
    labels={"schedule":"konfigurera teamets schema","scan":"starta imageskanning","status":"kontrollera CVE-databasen"}
    title={"schedule":"Ställ in teamets schema","scan":"Skanna containerbilder","status":"Kontrollera CVE-databasen"}.get(cve,"Sök "+cve)
    label=labels.get(cve,"visa "+cve)
    body="[Logga in och "+label+"]("+link+")\nPersonlig länk · giltig i 10 minuter."
    if cve=="schedule":
        body+="\nAutomatik aktiveras först när du sparar ett aktivt schema."
    elif shared:
        body+=("\nDelas med kanalens medlemmar inom din och kanalens godkända omfattning." if policy=="requester" else
               "\nDelas inom kanalmedlemmarnas gemensamma behörigheter.")
    return card_message(title,body,summary="**ACS · Bekräfta beställningen**",fields=[
        field("Omfattning",inert(namespace) if namespace else "Välj på nästa sida" if cve=="schedule" else "Dina godkända namespaces"),
        field("Resultat","Till teamkanalen" if shared else "Privat till dig")],footer="ACS · Säker inloggning")


def error_message(message):
    return card_message("Förfrågan kunde inte slutföras",message,summary="**ACS · Kontrollera beställningen**",color="#D97732",footer="ACS · Inga obehöriga fynd visas")


class Services:
    def __init__(self):
        self.auth_provider = os.getenv("AUTH_PROVIDER", "oidc")
        self.alerts = None
        if self.auth_provider not in {"oidc", "openshift"}:
            raise RuntimeError("AUTH_PROVIDER must be oidc or openshift")
        self.kube = os.getenv("KUBE_API", "https://kubernetes.default.svc").rstrip("/")
        self.rox = os.getenv("STACKROX_URL", "https://central.stackrox.svc:443").rstrip("/")
        self.mm = os.environ.get("MATTERMOST_INTERNAL_URL", "http://mattermost.cvebridge.svc:8065").rstrip("/")
        self.mm_public = os.environ.get("MATTERMOST_PUBLIC_URL", "http://localhost:18065").rstrip("/")
        self.public = os.environ.get("PUBLIC_URL", "http://localhost:18080").rstrip("/")
        self.bot_id = os.getenv("MATTERMOST_BOT_ID", "")
        self.cluster_id = os.environ.get("STACKROX_CLUSTER_ID", "")
        self.channel_scopes = json.loads(os.getenv("MATTERMOST_CHANNEL_SCOPES", "{}"))
        self.channel_policies = json.loads(os.getenv("MATTERMOST_CHANNEL_POLICIES", "{}"))
        self.schedule_scopes = json.loads(os.getenv("MATTERMOST_SCHEDULE_SCOPES", "{}"))
        self.schedule_managers = json.loads(os.getenv("MATTERMOST_SCHEDULE_MANAGERS", "{}"))
        self.schedule_user = os.getenv("SCHEDULE_SERVICE_USER", "")
        self.scheduled_credentials = False
        if (not isinstance(self.schedule_scopes, dict) or any(k not in self.channel_scopes or not isinstance(v,list)
                or not v or not set(v) <= set(self.channel_scopes[k]) for k,v in self.schedule_scopes.items())):
            raise RuntimeError("Schedule scopes must be approved subsets of channel scopes")
        if (not isinstance(self.schedule_managers, dict) or any(k not in self.schedule_scopes or not isinstance(v,list)
                or not v or any(not re.fullmatch(r"[a-z0-9]{26}", u) for u in v) for k,v in self.schedule_managers.items())):
            raise RuntimeError("Invalid schedule manager mapping")
        if self.schedule_scopes and not re.fullmatch(r"system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+", self.schedule_user):
            raise RuntimeError("Configure a dedicated Kubernetes service identity for scheduled jobs")
        if (not isinstance(self.channel_policies, dict) or
                any(k not in self.channel_scopes or v not in {"common", "requester"} for k,v in self.channel_policies.items())):
            raise RuntimeError("Invalid shared-channel policy configuration")
        if not isinstance(self.channel_scopes, dict):
            raise RuntimeError("MATTERMOST_CHANNEL_SCOPES must map channel IDs to namespace lists")
        for channel_id, namespaces in self.channel_scopes.items():
            if (not re.fullmatch(r"[a-z0-9]{26}", channel_id) or not isinstance(namespaces, list)
                    or not namespaces or len(namespaces) > 100
                    or any(not isinstance(n, str) or not NS.fullmatch(n) for n in namespaces)):
                raise RuntimeError("Invalid shared-channel namespace configuration")
        if self.cluster_id and not re.fullmatch(r"[a-zA-Z0-9-]+", self.cluster_id):
            raise RuntimeError("STACKROX_CLUSTER_ID must be a literal cluster ID")
        self.kube_context = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt")) if (SA_DIR / "ca.crt").exists() else None
        ca = os.getenv("STACKROX_CA_FILE")
        self.rox_context = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        mm_ca = os.getenv("MATTERMOST_CA_FILE")
        self.mm_context = ssl.create_default_context(cafile=mm_ca) if mm_ca else ssl.create_default_context()

    def kube_request(self, path, payload=None):
        token = (SA_DIR / "token").read_text().strip()  # projected tokens rotate
        return request_json(self.kube + path, payload=payload,
                            headers={"Authorization": "Bearer " + token}, context=self.kube_context)

    def openshift_identity(self, headers):
        """Verify the proxy's OAuth token with this cluster, never header groups.

        The token is used only for TokenReview and is never persisted in requests,
        jobs, schedules or reports. Browser traffic reaches this through loopback.
        """
        token = headers.get("X-Forwarded-Access-Token", "").strip()
        if not token or len(token) > 16384 or any(ord(c) < 33 for c in token):
            raise Problem(401, "Logga in via den privata länken för att fortsätta.")
        review = self.kube_request("/apis/authentication.k8s.io/v1/tokenreviews", {
            "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token}})
        status = review.get("status") or {}
        account = status.get("user") or {}
        user, groups = account.get("username"), account.get("groups", [])
        if (status.get("authenticated") is not True or status.get("error")
                or not isinstance(user, str) or not user or len(user) > 256
                or user.startswith("system:") or any(ord(c) < 32 for c in user)
                or not isinstance(groups, list) or len(groups) > 2000
                or any(not isinstance(g, str) or not g or len(g) > 256
                       or any(ord(c) < 32 for c in g) for g in groups)):
            raise Problem(401, "OpenShift-inloggningen kunde inte verifieras. Logga in igen.")
        return user, sorted(set(groups) | {"system:authenticated"})

    def allowed_namespaces(self, user, groups):
        result = []
        namespaces, continuation = [], ""
        while True:
            page = self.kube_request("/api/v1/namespaces?" + urlencode({"limit": 100, "continue": continuation}))
            namespaces.extend(item["metadata"]["name"] for item in page.get("items", []))
            continuation = page.get("metadata", {}).get("continue", "")
            if not continuation:
                break
        for namespace in namespaces:
            if self.permitted_namespace(user, groups, namespace):
                result.append(namespace)
        return sorted(result)

    def permitted_namespace(self, user, groups, namespace):
        sar = self.kube_request("/apis/authorization.k8s.io/v1/subjectaccessreviews", {
                "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                "spec": {"user": user, "groups": groups,
                         "resourceAttributes": {"namespace": namespace, "verb": "list", "group": "apps", "resource": "deployments"}}})
        status = sar.get("status", {})
        if status.get("evaluationError"):
            raise Problem(503, "Behörigheterna kunde inte kontrolleras. Inga fynd lämnades ut.")
        return status.get("allowed") is True and not status.get("denied")

    def rox_request(self, path, payload=None, *, capability="read", timeout=30):
        key = "STACKROX_SCHEDULE_TOKEN" if self.scheduled_credentials and capability in {"read", "scan"} else {"read": "STACKROX_TOKEN", "scan": "STACKROX_SCAN_TOKEN", "status": "STACKROX_STATUS_TOKEN"}[capability]
        token = os.environ.get(key, "")
        if not token or not self.cluster_id:
            raise Problem(503, "ACS-anslutningen är inte klar. Be drift kontrollera inställningarna.")
        return request_json(self.rox + path, payload=payload, headers={"Authorization": "Bearer " + token}, context=self.rox_context, timeout=timeout)

    def scheduled_scanner(self):
        service = Services()
        service.scheduled_credentials = True
        return service

    def database_status(self):
        component = os.getenv("STACKROX_SCANNER_COMPONENT", "SCANNER")
        if component not in {"SCANNER", "SCANNER_V4"}:
            raise Problem(503, "Skannerinställningen stöds inte. Be drift kontrollera den.")
        maximum = float(os.getenv("DATABASE_MAX_AGE_HOURS", "24"))
        result = {"kind": "status", "state": "unknown", "lastUpdated": None, "ageHours": None,
                  "checkedAt": utc_now(), "maxAgeHours": maximum, "component": component}
        try:
            data = self.rox_request("/v1/integrationhealth/vulndefinitions?component="+component, capability="status")
            stamp = data.get("lastUpdatedTimestamp")
            updated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc)-updated).total_seconds()/3600
            if age < -0.1 or maximum <= 0:
                return result
            result.update(lastUpdated=stamp, ageHours=round(max(0, age), 2), state="recent" if age <= maximum else "stale")
        except (Problem, ValueError, TypeError, AttributeError):
            LOG.warning("database_freshness_unverified")
        return result

    def inventory(self, namespaces):
        """Sensor's active pod inventory, scoped on every request and object.

        Use runtime digests rather than movable image tags. No global Kubernetes
        pod-read permission is granted to the integration's service account.
        """
        images, deployments, missing, pod_ids = {}, {}, set(), set()
        for namespace in namespaces:
            offset = 0
            while True:
                query = f"Cluster ID:{self.cluster_id}+Namespace:{namespace}"
                pods = self.rox_request("/v1/pods?"+urlencode({"query": query, "pagination.limit": 100, "pagination.offset": offset})).get("pods") or []
                for pod in pods:
                    if pod.get("clusterId") != self.cluster_id or pod.get("namespace") != namespace:
                        raise Problem(502, "Inventeringen matchar inte godkänd omfattning. Ingen skanning startades.")
                    live = [i for i in pod.get("liveInstances") or [] if not i.get("finished")]
                    if not live:
                        continue  # Historical/deleted pods are retained by Central.
                    pod_ids.add(pod["id"])
                    deployment_id = pod.get("deploymentId")
                    if not deployment_id:
                        missing.add((namespace, pod["id"], "workload-pending"))
                        continue
                    if deployment_id not in deployments:
                        deployments[deployment_id] = self.rox_request("/v1/deployments/"+quote(deployment_id, safe=""))
                    deployment = deployments[deployment_id]
                    if deployment.get("namespace") != namespace or deployment.get("clusterId") != self.cluster_id:
                        raise Problem(502, "Arbetslasten matchar inte godkänd omfattning. Ingen skanning startades.")
                    containers = {c.get("name"): c for c in deployment.get("containers") or []}
                    references = [(i.get("containerName"), i.get("imageDigest")) for i in live]
                    # Completed init containers still contribute image dependencies.
                    references += [(c.get("name"), (c.get("image") or {}).get("id")) for c in containers.values() if c.get("type") == "INIT"]
                    for name, digest in references:
                        container = containers.get(name) or {}
                        image = container.get("image") or {}
                        full_name = (image.get("name") or {}).get("fullName", "")
                        if not digest or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest) or not full_name:
                            missing.add((namespace, pod["id"], name))
                            continue
                        repo = full_name.split("@", 1)[0]
                        if ":" in repo.rsplit("/", 1)[-1]:
                            repo = repo.rsplit(":", 1)[0]
                        if not re.fullmatch(r"[a-zA-Z0-9._:/-]+", repo):
                            missing.add((namespace, pod["id"], name))
                            continue
                        entry = images.setdefault(digest, {"digest": digest, "imageName": repo+"@"+digest, "targets": []})
                        target = {"namespace": namespace, "deployment": deployment["name"]}
                        if target not in entry["targets"]:
                            entry["targets"].append(target)
                if len(pod_ids) > 2000 or len(images) > 100:
                    raise Problem(413, "Urvalet överstiger 2 000 poddar eller 100 containerbilder. Kör /cve scan med ett namespace.")
                if len(pods) < 100:
                    break
                offset += len(pods)
                if offset > 10000:
                    raise Problem(413, "Inventeringen är för stor. Avgränsa till ett namespace.")
        return {"images": list(images.values()), "pods": len(pod_ids), "missing": len(missing)}

    def scan(self, namespaces, authorize, progress, *, force=True):
        start = time.monotonic()
        authorize()
        inventory = self.inventory(namespaces)
        rows, failed, scanned, components, errors, warnings, partial = [], 0, 0, 0, [], [], 0
        truncated = False
        scan_times = []
        for number, entry in enumerate(inventory["images"]):
            authorize()  # Recheck live grants and audience before each scan.
            if time.monotonic()-start > 1800:
                failed += len(inventory["images"])-number
                errors.append({"image": entry["imageName"], "reason": "Körningens tidsgräns nåddes"})
                break
            progress(f"Skannar containerbild {number+1}/{len(inventory['images'])}")
            payload = {"imageName": entry["imageName"], "force": True}
            if os.getenv("STACKROX_DELEGATE_SCAN", "false").lower() == "true":
                payload.update(cluster=self.cluster_id, namespace=entry["targets"][0]["namespace"])
            attempt = datetime.now(timezone.utc)
            try:
                image = (self.rox_request("/v1/images/scan", payload, capability="scan", timeout=180) if force else
                         self.rox_request("/v1/images/"+quote(entry["digest"],safe="")+"?strip_description=true"))
                scan = image.get("scan") or {}
                stamp = scan.get("scanTime")
                scan_time = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if (image.get("id") != entry["digest"] or "MISSING_SCAN_DATA" in (image.get("notes") or []) or
                        (force and (attempt-scan_time).total_seconds() > 2)):
                    raise Problem(502, "Ett nytt skanningsresultat kunde inte verifieras.")
                scanned += 1
                scan_times.append({"image": entry["imageName"], "scanTime": stamp})
                components += len(scan.get("components") or [])
                if image.get("notes"):
                    warnings.append({"image": entry["imageName"], "notes": image["notes"]})
                scan_notes = [n for n in scan.get("notes") or [] if n != "UNSET"]
                if scan_notes or "MISSING_METADATA" in (image.get("notes") or []) or not scan.get("components"):
                    partial += 1
                    warnings.append({"image": entry["imageName"], "scanNotes": scan_notes or ["PARTIAL_SCAN_DATA"]})
                for component in scan.get("components") or []:
                    for vuln in component.get("vulns") or []:
                        if not CVE.fullmatch(vuln.get("cve", "").upper()):
                            continue
                        if len(rows)+len(entry["targets"]) > 20000:
                            truncated = True
                            continue
                        for target in entry["targets"]:
                            rows.append({**target, "image": entry["imageName"], "imageId": entry["digest"],
                                         "component": component.get("name", ""), "version": component.get("version", ""),
                                         "source": component.get("source") or "OS", "location": component.get("location") or "",
                                         "cve": vuln["cve"], "fixedBy": vuln.get("fixedBy", ""), "cvss": vuln.get("cvss") or 0})
            except (Problem, ValueError, TypeError, AttributeError):
                failed += 1
                errors.append({"image": entry["imageName"], "reason": "Ett komplett skanningsresultat kunde inte verifieras"})
        authorize()
        return {"kind": "scan", "mode": "scan" if force else "report", "namespaces": namespaces, "rows": rows, "scannedImages": scanned,
                "totalImages": len(inventory["images"]), "failedImages": failed, "unscannedImages": inventory["missing"], "partialImages": partial,
                "pods": inventory["pods"], "components": components, "errors": errors, "warnings": warnings,
                "truncated": truncated, "scanTimes": scan_times, "database": self.database_status(),
                "finishedAt": utc_now(), "durationSeconds": round(time.monotonic()-start)}

    def lookup(self, cve, namespaces):
        rows, scanned_images, unscanned_images = [], set(), set()
        seen_images = {}
        # Each request is explicitly scoped to ONE authorized namespace AND cluster.
        # Inspect images of all its deployments so scan coverage is not confused
        # with an empty CVE search result. Recheck scope on every returned object.
        for namespace in namespaces:
            offset = 0
            while True:
                query = f"Cluster ID:{self.cluster_id}+Namespace:{namespace}"
                page = self.rox_request("/v1/deployments?" + urlencode({"query": query, "pagination.limit": 100, "pagination.offset": offset}))
                items = page.get("deployments") or []
                for item in items:
                    if item.get("namespace") != namespace or item.get("clusterId") != self.cluster_id:
                        continue
                    deployment = self.rox_request("/v1/deployments/" + quote(item["id"], safe=""))
                    if deployment.get("namespace") != namespace or deployment.get("clusterId") != self.cluster_id:
                        raise Problem(502, "Tjänstens svar matchar inte godkänd omfattning. Inga fynd lämnades ut.")
                    containers = deployment.get("containers") or []
                    if not containers:
                        unscanned_images.add((namespace, item["id"], "inventory-pending"))
                    for container in containers:
                        image = container.get("image") or {}
                        image_id = image.get("id", "")
                        if not image_id:
                            unscanned_images.add((namespace, item["id"], container.get("name")))
                            continue
                        if image_id not in seen_images:
                            seen_images[image_id] = self.rox_request("/v1/images/" + quote(image_id, safe="") + "?strip_description=true")
                        image = seen_images[image_id]
                        scan = image.get("scan") or {}
                        if not scan.get("scanTime") or "MISSING_SCAN_DATA" in (image.get("notes") or []):
                            unscanned_images.add((namespace, image_id))
                            continue
                        scanned_images.add((namespace, image_id))
                        for component in scan.get("components") or []:
                            for vuln in component.get("vulns") or []:
                                if vuln.get("cve", "").upper() == cve:
                                    rows.append({"namespace": namespace, "deployment": deployment["name"],
                                                 "image": (image.get("name") or {}).get("fullName", image_id),
                                                 "component": component.get("name", ""), "version": component.get("version", ""),
                                                 "source": component.get("source") or "OS", "location": component.get("location") or "",
                                                 "fixedBy": vuln.get("fixedBy", ""), "cvss": vuln.get("cvss", "")})
                if len(items) < 100:
                    break
                offset += len(items)
                if offset > 10000:
                    raise Problem(503, "Resultatet är för stort. Avgränsa till ett namespace.")
        return {"cve": cve, "namespaces": namespaces, "rows": rows,
                "scannedImages": len(scanned_images), "unscannedImages": len(unscanned_images)}

    def mm_request(self, path, payload=None):
        token = os.environ.get("MATTERMOST_TOKEN", "")
        if not token:
            raise Problem(503, "Mattermost-anslutningen är inte klar. Be drift kontrollera inställningarna.")
        return request_json(self.mm + path, payload=payload, headers={"Authorization": "Bearer " + token}, context=self.mm_context)

    def bot_profile(self):
        user = self.mm_request("/api/v4/users/me")
        if (not self.bot_id or user.get("id") != self.bot_id or user.get("is_bot") is not True
                or "system_admin" in user.get("roles", "").split()):
            raise Problem(503, "Integrationen behöver ett vanligt botkonto utan administratörsroll.")
        return user

    def upload_report(self, channel_id, result):
        """Upload only the authorized report, using the bot's channel membership."""
        raw = json.dumps({k:v for k,v in result.items() if k != "reportUrl"}, ensure_ascii=False, indent=2).encode()
        if len(raw) > 8*1024*1024:
            raise Problem(413, "Rapporten är för stor att dela. Kör /cve scan med ett namespace.")
        boundary = "acs"+secrets.token_hex(24)
        body = ("--"+boundary+'\r\nContent-Disposition: form-data; name="files"; filename="acs-scan-report.json"\r\nContent-Type: application/json\r\n\r\n').encode()+raw+("\r\n--"+boundary+"--\r\n").encode()
        try:
            with urlopen(Request(self.mm+"/api/v4/files?"+urlencode({"channel_id": channel_id}), data=body,
                                 headers={"Authorization": "Bearer "+os.environ["MATTERMOST_TOKEN"],
                                          "Content-Type": "multipart/form-data; boundary="+boundary}), context=self.mm_context, timeout=60) as response:
                files = json.loads(response.read(1024*1024)).get("file_infos") or []
            if len(files) != 1 or not re.fullmatch(r"[a-z0-9]{26}", files[0].get("id", "")):
                raise ValueError("Invalid upload result")
            return [files[0]["id"]]
        except (HTTPError, URLError, TimeoutError, ValueError):
            raise Problem(502, "Rapportfilen kunde inte laddas upp. Ingen sammanfattning publicerades.") from None

    def command_reply(self, text, **extra):
        return {"response_type": "ephemeral", "username": "ACS", "icon_url": self.mm_public + "/api/v4/users/" + self.bot_id + "/image",
                "text": text, **extra}

    def expected_user(self, user_id):
        if not re.fullmatch(r"[a-z0-9]{26}", user_id):
            raise Problem(400, "Mattermost-kontot kunde inte identifieras.")
        user = self.mm_request("/api/v4/users/" + user_id)
        if user.get("delete_at", 0):
            raise Problem(403, "Kontot behöver en godkänd identitetskoppling. Kontakta drift.")
        if self.auth_provider == "openshift":
            mappings = json.loads(os.getenv("MATTERMOST_KUBE_USER_MAP", "{}"))
            mapped = mappings.get(user_id)
            if (not isinstance(mapped, str) or not mapped or len(mapped) > 256
                    or mapped.startswith("system:") or any(ord(c) < 32 for c in mapped)):
                raise Problem(403, "Kontot behöver en godkänd koppling till OpenShift. Kontakta drift.")
            return "openshift:" + mapped
        # A normal Mattermost integration account cannot see email_verified for
        # other people. Prefer an administrator-approved immutable user-ID map;
        # never turn a user-editable profile email into a trusted identity.
        mappings = json.loads(os.environ.get("MATTERMOST_IDENTITY_MAP", "{}"))
        mapped = mappings.get(user_id)
        if mapped:
            if not isinstance(mapped, str) or "@" not in mapped or len(mapped) > 256:
                raise Problem(503, "Identitetskopplingen är felaktig. Kontakta drift.")
            return mapped.lower()
        email = user.get("email", "")
        if not email or user.get("email_verified") is not True:
            raise Problem(403, "Kontot behöver en godkänd identitetskoppling. Kontakta drift.")
        # The command's user_name and any submitted email are deliberately ignored.
        return email.lower()

    def callback_path(self, response_url):
        actual = urlsplit(response_url)
        allowed = [urlsplit(self.mm), urlsplit(self.mm_public)]
        if (actual.scheme, actual.netloc) not in [(x.scheme, x.netloc) for x in allowed]:
            raise Problem(400, "Svarslänken kunde inte verifieras. Kör kommandot igen.")
        if actual.query or actual.fragment or not re.fullmatch(r"/hooks/commands/[a-zA-Z0-9]+", actual.path):
            raise Problem(400, "Svarslänken är ogiltig. Kör kommandot igen.")
        return actual.path

    def shared_audience(self, channel_id, requester_id, allowed):
        """Fail closed unless an approved private channel has a verified audience.

        Only individually checkable Kubernetes grants are used for other people.
        Their OIDC groups cannot be inferred from Mattermost membership.
        """
        if channel_id not in self.channel_scopes:
            return None
        channel = self.mm_request("/api/v4/channels/" + channel_id)
        if channel.get("id") != channel_id or channel.get("type") != "P" or channel.get("delete_at", 0):
            raise Problem(403, "Delade resultat kräver en godkänd och aktiv privat kanal.")
        integration_id = self.bot_profile().get("id")
        if not re.fullmatch(r"[a-z0-9]{26}", integration_id or ""):
            raise Problem(503, "Kanalens medlemmar kunde inte verifieras. Inga fynd delas.")
        member_ids = set()
        for page_number in range(6):
            members = self.mm_request("/api/v4/channels/" + channel_id + "/members?" +
                                      urlencode({"page": page_number, "per_page": 200}))
            if not isinstance(members, list):
                raise Problem(503, "Kanalens medlemmar kunde inte verifieras. Inga fynd delas.")
            for member in members:
                member_id = member.get("user_id", "")
                if not re.fullmatch(r"[a-z0-9]{26}", member_id) or member.get("channel_id") != channel_id:
                    raise Problem(503, "Kanalens medlemmar kunde inte verifieras. Inga fynd delas.")
                member_ids.add(member_id)
            if len(members) < 200:
                break
        else:
            raise Problem(403, "Kanalen är för stor för den här behörighetskontrollen.")
        if requester_id not in member_ids or integration_id not in member_ids:
            raise Problem(403, "Du och boten måste vara medlemmar i den privata kanalen.")
        candidates = set(allowed) & set(self.channel_scopes[channel_id])
        policy = self.channel_policies.get(channel_id, "common")
        kube_users = json.loads(os.getenv("MATTERMOST_KUBE_USER_MAP", "{}"))
        for member_id in sorted(member_ids - {integration_id}):
            email = self.expected_user(member_id)
            if policy == "requester":
                continue  # Admin approved this channel as a disclosure boundary.
            kube_user = kube_users.get(member_id)
            if kube_user is None and os.getenv("IDENTITY_HEADER", "X-Forwarded-Email") == "X-Forwarded-Email":
                kube_user = os.getenv("IDENTITY_PREFIX", "") + email
            if not isinstance(kube_user, str) or not kube_user or len(kube_user) > 256 or any(ord(c) < 32 for c in kube_user):
                raise Problem(403, "Varje kanalmedlem behöver en godkänd Kubernetes-identitet.")
            candidates = {namespace for namespace in candidates
                          if self.permitted_namespace(kube_user, ["system:authenticated"], namespace)}
        if not candidates:
            raise Problem(403, "Kanalmedlemmarna saknar gemensamt tillåtna namespaces. Inga fynd delades.")
        return {"namespaces": sorted(candidates), "members": sorted(member_ids), "policy": policy}

    def schedule_service_scope(self, channel_id):
        if channel_id not in self.schedule_scopes:
            raise Problem(403, "Automatik är inte godkänd för denna kanal. Be plattformsteamet ansluta kanalen.")
        namespace = self.schedule_user.split(":")[2]
        groups = ["system:serviceaccounts", "system:serviceaccounts:"+namespace, "system:authenticated"]
        return [n for n in self.schedule_scopes[channel_id]
                if n in self.channel_scopes.get(channel_id, []) and self.permitted_namespace(self.schedule_user, groups, n)]

    def scheduled_audience(self, channel_id, selected):
        # This is the actual reporter service identity, never a saved human login.
        allowed = self.schedule_service_scope(channel_id)
        audience = self.shared_audience(channel_id, self.bot_id, allowed)
        if not audience or not set(selected) <= set(audience["namespaces"]):
            raise Problem(403, "Rapporttjänsten eller kanalen saknar aktuellt tillstånd för schemats namespaces.")
        return audience

    def send_callback(self, path, result, *, shared=False, channel_id=""):
        if shared:
            if channel_id not in self.channel_scopes:
                raise Problem(403, "Kanalen är inte ansluten till ACS-tjänsten.")
            self.bot_profile()
            if self.alerts is not None and result.get("kind") == "scan":
                return self.alerts.publish(self, channel_id, result)
            formatted = result_message(result, shared=True)
            # Authenticate as the actual ACS account. A slash callback would
            # retain the requester's user_id even when its display name changes.
            return self.mm_request("/api/v4/posts", {"channel_id": channel_id, "message": formatted["text"],
                                                    "file_ids": result.get("reportFileIds", []),
                                                    "props": {"attachments": formatted["attachments"]}})
        # Owner-only callbacks retain Mattermost's ephemeral delivery semantics.
        formatted = result_message(result)
        request_json(self.mm + path, payload=self.command_reply(**formatted), context=self.mm_context, expect_json=False)


class CveAlerts:
    """Remember findings from confirmed channel reports, independently of jobs.

    A missing finding never erases its history. Only an acknowledged post
    advances the baseline, so a rejected publication does not consume an alert.
    The worker serializes scans; this lock also protects direct publish callers.
    """
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.enabled = os.getenv("CVE_ALERTS_ENABLED", "true").lower() == "true"
        self.first_report = os.getenv("CVE_ALERT_FIRST_REPORT", "false").lower() == "true"
        try:
            self.minimum = float(os.getenv("CVE_ALERT_MIN_CVSS", "9"))
            if not 0 <= self.minimum <= 10:
                raise ValueError()
        except ValueError:
            raise RuntimeError("CVE_ALERT_MIN_CVSS must be between 0 and 10") from None
        with store.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS cve_seen (channel_id TEXT, cluster_id TEXT, cve TEXT, reported_at REAL, PRIMARY KEY(channel_id,cluster_id,cve))")
            db.execute("CREATE TABLE IF NOT EXISTS cve_baselines (channel_id TEXT, cluster_id TEXT, namespace TEXT, created_at REAL, PRIMARY KEY(channel_id,cluster_id,namespace))")

    def preview(self, channel, cluster, result):
        with self.store.connect() as db:
            known = {r[0] for r in db.execute("SELECT cve FROM cve_seen WHERE channel_id=? AND cluster_id=?",(channel,cluster))}
            covered = {r[0] for r in db.execute("SELECT namespace FROM cve_baselines WHERE channel_id=? AND cluster_id=?",(channel,cluster))}
        observed = {r["cve"] for r in result["rows"] if CVE.fullmatch(r.get("cve", ""))}
        candidates = [r for r in result["rows"] if r.get("cve") in observed-known
                      and (self.first_report or r.get("namespace") in covered)]
        new = sorted({r["cve"] for r in candidates})
        urgent = sorted({r["cve"] for r in candidates if score(r) >= self.minimum}) if self.enabled else []
        return {"newCves":new, "alertCves":urgent,
                "alertBaseline":not self.first_report and not (set(result["namespaces"]) & covered)}

    def publish(self, services, channel, result):
        with self.lock:
            change = self.preview(channel, services.cluster_id, result)
            rendered = result_message({**result, **change}, shared=True)
            if change["alertCves"]:
                count = len(change["alertCves"])
                scores = dict.fromkeys(change["alertCves"],0)
                for row in result["rows"]:
                    if row["cve"] in scores:
                        scores[row["cve"]] = max(scores[row["cve"]],score(row))
                identifiers = " · ".join(inert(cve,30) for cve in sorted(scores,key=lambda c:(-scores[c],c))[:3])
                if count>3:
                    identifiers += f" · +{count-3} fler"
                rendered["text"] = f"@channel **Nytt säkerhetslarm · {count} CVE:er**\n"+identifiers+"\n"+rendered["text"]
            post = services.mm_request("/api/v4/posts", {"channel_id":channel, "message":rendered["text"],
                "file_ids":result.get("reportFileIds",[]), "props":{"attachments":rendered["attachments"],
                    "cvebridge_new_cves":change["newCves"], "cvebridge_alert_cves":change["alertCves"]}})
            if not isinstance(post,dict) or not post.get("id"):
                raise Problem(502,"Rapportleveransen kunde inte bekräftas. Kontrollera kanalen innan du försöker igen.")
            complete = not (result["failedImages"] or result["unscannedImages"] or result.get("partialImages") or result.get("truncated"))
            now = time.time()
            with self.store.connect() as db:
                db.executemany("INSERT OR IGNORE INTO cve_seen VALUES (?,?,?,?)",
                    [(channel,services.cluster_id,cve,now) for cve in sorted({r["cve"] for r in result["rows"] if CVE.fullmatch(r.get("cve", ""))})])
                if complete:
                    db.executemany("INSERT OR IGNORE INTO cve_baselines VALUES (?,?,?,?)",
                        [(channel,services.cluster_id,n,now) for n in result["namespaces"]])
            result.update(change)
            return post


class Store:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, created REAL, email TEXT, cve TEXT, namespace TEXT, callback TEXT)")
            if "claimed" not in [r[1] for r in conn.execute("PRAGMA table_info(requests)")]:
                conn.execute("ALTER TABLE requests ADD COLUMN claimed INTEGER NOT NULL DEFAULT 0")
            for column in ["channel_id", "mm_user_id"]:
                if column not in [r[1] for r in conn.execute("PRAGMA table_info(requests)")]:
                    conn.execute("ALTER TABLE requests ADD COLUMN " + column + " TEXT NOT NULL DEFAULT ''")
            if "shared_requested" not in [r[1] for r in conn.execute("PRAGMA table_info(requests)")]:
                conn.execute("ALTER TABLE requests ADD COLUMN shared_requested INTEGER NOT NULL DEFAULT 0")
            conn.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, email TEXT, created REAL, state TEXT, progress TEXT, result TEXT, error TEXT)")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def create(self, email, cve, namespace, callback, channel_id="", mm_user_id="", *, shared=False):
        email = canonical_account(email)
        request_id = secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute("DELETE FROM requests WHERE created < ?", (time.time() - 600,))
            if conn.execute("SELECT COUNT(*) FROM requests WHERE email=? AND created>?", (email, time.time()-60)).fetchone()[0] >= 20:
                raise Problem(429, "För många beställningar. Försök igen om en minut.")
            conn.execute("INSERT INTO requests (id,created,email,cve,namespace,callback,channel_id,mm_user_id,shared_requested) VALUES (?,?,?,?,?,?,?,?,?)", (request_id, time.time(), email, cve, namespace, callback, channel_id, mm_user_id, int(shared)))
        return request_id

    def get(self, request_id, email):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM requests WHERE id=? AND created>?", (request_id, time.time()-600)).fetchone()
        if not row:
            raise Problem(404, "Länken har gått ut. Kör kommandot i Mattermost igen.")
        if not hmac.compare_digest(row["email"].encode(), canonical_account(email).encode()):
            raise Problem(403, "Logga in med kontot som gjorde beställningen i Mattermost.")
        return dict(row)

    def consume(self, request_id):
        with self.connect() as conn:
            conn.execute("DELETE FROM requests WHERE id=?", (request_id,))

    def claim(self, request_id):
        with self.connect() as conn:
            changed = conn.execute("UPDATE requests SET claimed=1 WHERE id=? AND claimed=0 AND created>?", (request_id, time.time()-600)).rowcount
        if not changed:
            raise Problem(409, "Beställningen behandlas redan eller har gått ut. Kör kommandot igen vid behov.")

    def release(self, request_id):
        with self.connect() as conn:
            conn.execute("UPDATE requests SET claimed=0 WHERE id=?", (request_id,))

    def create_job(self, email):
        job_id = secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute("DELETE FROM jobs WHERE created<?", (time.time()-14400,))
            conn.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?)", (job_id, canonical_account(email), time.time(), "running", "Inventerar poddar och images", "", ""))
        return job_id

    def update_job(self, job_id, *, state="running", progress="", result=None, error=""):
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET state=?,progress=?,result=?,error=? WHERE id=?",
                         (state, progress, json.dumps(result) if result is not None else "", error, job_id))

    def get_job(self, job_id, email):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=? AND created>?", (job_id, time.time()-14400)).fetchone()
        if not row:
            raise Problem(404, "Rapporten har gått ut. Kör /cve scan igen.")
        if not hmac.compare_digest(row["email"].encode(), canonical_account(email).encode()):
            raise Problem(403, "Skanningen tillhör ett annat konto.")
        row = dict(row)
        row["result"] = json.loads(row["result"]) if row["result"] else None
        return row


class ScanRunner:
    """One bounded worker; restart never silently publishes an interrupted job."""
    def __init__(self, services, store):
        self.services, self.store = services, store
        self.lock = threading.Lock()
        with store.connect() as conn:
            conn.execute("UPDATE jobs SET state='failed', error='Tjänsten startades om under skanningen. Kör /cve scan igen.' WHERE state='running'")

    def start(self, saved, user, groups, selected, audience, identity_refresh=None):
        if not self.lock.acquire(blocking=False):
            raise Problem(429, "En annan skanning pågår. Försök igen när den är klar.")
        try:
            job_id = self.store.create_job(saved["email"])
            threading.Thread(target=self.run, args=(job_id, saved, user, list(groups), list(selected), audience, identity_refresh), daemon=True).start()
            return job_id
        except Exception:
            self.lock.release()
            raise

    def run(self, job_id, saved, user, groups, selected, audience, identity_refresh=None):
        def authorize():
            current_groups = groups
            if identity_refresh:
                current_user, current_groups = identity_refresh()
                if current_user != user:
                    raise Problem(403, "Inloggningen ändrades. Inga fynd delades.")
            fresh_allowed = self.services.allowed_namespaces(user, current_groups)
            if not set(selected) <= set(fresh_allowed):
                raise Problem(403, "Din namespace-behörighet ändrades. Inga fynd delades.")
            if audience:
                fresh = self.services.shared_audience(saved["channel_id"], saved["mm_user_id"], fresh_allowed)
                if (not fresh or fresh["members"] != audience["members"] or fresh.get("policy") != audience.get("policy")
                        or not set(selected) <= set(fresh["namespaces"])):
                    raise Problem(403, "Kanalmedlemskap eller delningsbehörigheter ändrades. Inga fynd delades.")
        try:
            result = self.services.scan(selected, authorize, lambda progress: self.store.update_job(job_id, progress=progress))
            result["sharingPolicy"] = audience.get("policy", "common") if audience else "private"
            result["reportUrl"] = self.services.public+"/jobs/"+job_id
            authorize()
            if audience:
                self.services.bot_profile()
                result["reportFileIds"] = self.services.upload_report(saved["channel_id"], result)
                authorize()
            self.services.send_callback(saved["callback"], result, shared=bool(audience), channel_id=saved["channel_id"])
            result["delivery"] = "channel" if audience else "private"
            self.store.update_job(job_id, state="done", result=result)
        except Problem as exc:
            self.store.update_job(job_id, state="failed", error=exc.message)
        except Exception:
            LOG.exception("scan_job_failed")
            self.store.update_job(job_id, state="failed", error="Skanningen misslyckades. Leveransen är inte bekräftad; be drift kontrollera tjänsterna.")
        finally:
            self.lock.release()


def canonical_account(account):
    # OpenShift usernames are case-sensitive; email owners remain compatible
    # with the existing OIDC request/job database.
    return account if account.startswith("openshift:") else account.lower()


def login_account(headers, user):
    if os.getenv("AUTH_PROVIDER", "oidc") == "openshift":
        return "openshift:" + user
    return headers.get("X-Forwarded-Email", "").strip().lower()


def identity(headers, services=None):
    if os.getenv("AUTH_PROVIDER", "oidc") == "openshift":
        if services is None:
            raise Problem(503, "OpenShifts identitetskontroll kan inte nås. Försök igen senare.")
        return services.openshift_identity(headers)
    header = os.getenv("IDENTITY_HEADER", "X-Forwarded-Email")
    user = headers.get(header, "").strip()
    if not user or len(user) > 256 or any(ord(c) < 32 for c in user):
        raise Problem(401, "Logga in via den privata länken för att fortsätta.")
    groups = [g.strip() for g in headers.get("X-Forwarded-Groups", "").split(",") if g.strip()]
    groups = [g for g in groups if not g.startswith("system:")]
    return os.getenv("IDENTITY_PREFIX", "") + user, groups + ["system:authenticated"]


def select_namespaces(allowed, namespace):
    if namespace and namespace not in allowed:
        raise Problem(403, "Du saknar behörighet till det namespacet.")
    if not allowed:
        raise Problem(403, "Kontot saknar tillåtna namespaces. Kontakta drift.")
    return [namespace] if namespace else allowed


def page(title, body):
    return ("<!doctype html><html lang='sv'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            "<title>" + html.escape(title) + " · CVE Bridge</title><style>"
            "*{box-sizing:border-box}body{margin:0;background:#101924;color:#e9eef5;font:16px system-ui;line-height:1.6}"
            "main{max-width:1100px;margin:60px auto;padding:24px}a{color:#88d9cc}h1{font-size:38px;letter-spacing:-1px}"
            ".tag{color:#83d9c9;font-size:13px;letter-spacing:2px}section{background:#192637;padding:24px;border:1px solid #314356;border-radius:12px;margin:24px 0}"
            "input,select,button{font:inherit;padding:12px;border-radius:7px;border:1px solid #526477;margin:6px 8px 6px 0}"
            "button{background:#83d9c9;color:#10232b;cursor:pointer}table{width:100%;border-collapse:collapse;font-size:14px}"
            "th,td{text-align:left;padding:12px;border-bottom:1px solid #35465a;overflow-wrap:anywhere}.muted{color:#acbacb}"
            "</style><main><div class='tag'>CVE BRIDGE / DEVSECOPS LAB</div><h1>" + html.escape(title) + "</h1>" + body + "</main></html>").encode()


class Handler(BaseHTTPRequestHandler):
    services = None
    store = None
    runner = None
    schedules = None
    scheduler = None
    native_schedules = None
    public_listener = False

    def log_request(self, code="-", size="-"):
        if self.path.startswith("/slash/cve/dialog/"):
            LOG.info("dialog_http status=%s", code)
        else:
            super().log_request(code, size)

    def native_schedule_post(self, key):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 32768:
                raise Problem(413, "Formuläret saknas eller är för stort.")
            payload = json.loads(self.rfile.read(length))
            result = self.native_schedules.submit(key, payload)
            return self.reply(200, result)
        except (Problem, ScheduleError) as exc:
            return self.reply(exc.status if exc.status in {401,403} else 200, {"error":exc.message})
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {"error":"Formuläret kunde inte läsas."})
        except Exception:
            LOG.exception("native_schedule_failed")
            return self.reply(500, {"error":"Schemat kunde inte behandlas. Kör /cve schedule igen och kontrollera inställningarna."})

    def schedule_context(self, saved, user, groups):
        channel = saved["channel_id"]
        if not saved["shared_requested"] or channel not in self.services.schedule_scopes:
            raise Problem(403, "Automatik kräver en godkänd privat teamkanal.")
        managers = self.services.schedule_managers.get(channel)
        if managers and saved["mm_user_id"] not in managers:
            raise Problem(403, "Du är inte utsedd att ändra kanalens schema.")
        allowed = self.services.allowed_namespaces(user, groups)
        actor_audience = self.services.shared_audience(channel, saved["mm_user_id"], allowed)
        service_audience = self.services.scheduled_audience(channel, [])
        current = self.schedules.get(channel)
        existing = set(current["config"]["namespaces"]) if current else set()
        # A team member may preserve previously approved scope when editing
        # frequency, but adding a namespace requires their own live access.
        candidates = (set(actor_audience["namespaces"]) | existing) & set(service_audience["namespaces"])
        if not candidates:
            raise Problem(403, "Inga namespaces är godkända både för teamet och rapporttjänsten.")
        return current, sorted(candidates), service_audience

    def schedule_form(self, request_id, saved, user, groups):
        current, candidates, audience = self.schedule_context(saved, user, groups)
        config = current["config"] if current else {"days": list(range(7)), "times": ["08:00"],
                  "timezone": os.getenv("SCHEDULE_DEFAULT_TIMEZONE", "Europe/Stockholm"), "mode": "scan", "namespaces": candidates}
        checked = lambda yes: " checked" if yes else ""
        esc = html.escape
        body = "<p>Välj när ACS ska skanna teamets images och dela rapporten i den här kanalen. Du kan ändra och pausa schemat här senare.</p>"
        body += "<section><p><strong>"+("Aktivt schema" if current and current["enabled"] else "Pausat schema" if current else "Första konfigurationen — inget schema är aktiverat ännu")+"</strong></p>"
        if current and current["next_due"]:
            body += "<p>Nästa körning: "+readable_time(datetime.fromtimestamp(current["next_due"],timezone.utc).isoformat())+".</p>"
        body += "<form method='post' action='/requests/"+esc(request_id)+"/schedule'>"
        body += "<input type='hidden' name='csrf' value='"+hashlib.sha256(("schedule:"+request_id).encode()).hexdigest()+"'>"
        body += "<input type='hidden' name='revision' value='"+str(current["revision"] if current else 0)+"'>"
        body += "<h2>Dagar</h2>"+" ".join("<label style='display:inline-block;margin-right:14px'><input type='checkbox' name='days' value='"+str(i)+"'"+checked(i in config["days"])+">"+day+"</label>" for i,day in enumerate(DAY_NAMES))
        body += "<h2>Tider och tidszon</h2><p><label>Tider, separerade med komma<br><input name='times' aria-label='Tider' value='"+esc(", ".join(config["times"]))+"' required></label></p>"
        body += "<p><label>Tidszon<br><input name='timezone' aria-label='Tidszon' value='"+esc(config["timezone"])+"' required></label></p><p class='muted'>Exempel: 08:00, 15:00 och Europe/Stockholm. Högst fyra gånger per vald dag, minst en timme mellan tiderna.</p>"
        body += "<h2>Vad ska göras?</h2><select name='mode' aria-label='Körningstyp'>"+"".join("<option value='"+key+"'"+(" selected" if config["mode"] == key else "")+">"+label+"</option>" for key,label in [("scan","Ny imageskanning och rapport"),("report","Rapport från senaste befintliga skanningar")])+"</select>"
        body += "<h2>Namespaces</h2>"+" ".join("<label style='display:inline-block;margin-right:14px'><input type='checkbox' name='namespaces' value='"+esc(n)+"'"+checked(n in config["namespaces"])+">"+esc(n)+"</label>" for n in candidates)
        body += "<p><label><input type='checkbox' name='enabled' value='yes'"+checked(not current or current["enabled"])+">Aktivera automatiska körningar</label></p>"
        body += "<p>Rapporter och bilagor blir synliga för kanalens medlemmar. Datorn och tjänsterna behöver vara igång vid körning. Vid övergång till sommartid hoppas en tid som inte finns över; en upprepad vintertid körs en gång.</p>"
        body += "<button name='action' value='save'>Spara schema</button>"
        if current and current["enabled"]:
            body += "<button name='action' value='run'>Provkör senast sparade schema</button>"
        body += "</form></section>"+self.schedule_history(saved["channel_id"])
        # Chrome uses Origin:null for form POSTs under no-referrer. Preserve
        # a verifiable same-origin Origin while never referring to other sites.
        return self.reply(200, page("Teamets automatiska skanningar", body), "text/html; charset=utf-8", headers={"Referrer-Policy":"same-origin"})

    def schedule_history(self, channel_id):
        names = {"queued":"Väntar", "running":"Pågår", "done":"Levererad", "partial":"Levererad med luckor", "failed":"Misslyckad", "missed":"Missad", "cancelled":"Avbruten", "interrupted":"Avbruten vid omstart"}
        rows = self.schedules.history(channel_id)
        body = "<section><h2>Senaste körningar</h2>"
        if not rows:
            return body+"<p>Inga körningar ännu.</p></section>"
        body += "<table><tr><th>Planerad tid (UTC)</th><th>Status</th><th>Information</th></tr>"
        for row in rows:
            body += "<tr><td>"+readable_time(datetime.fromtimestamp(row["due"], timezone.utc).isoformat())+"</td><td>"+names.get(row["state"], "Okänd")+"</td><td>"+html.escape(row["error"] or row["progress"] or "")+"</td></tr>"
        return body+"</table></section>"

    def schedule_post(self):
        path = urlsplit(self.path).path
        request_id = path.removeprefix("/requests/").removesuffix("/schedule")
        if self.headers.get("Origin", "") != self.services.public:
            raise Problem(403, "Ogiltigt formulärursprung. Öppna länken från /cve schedule igen.")
        user, groups = identity(self.headers, self.services)
        saved = self.store.get(request_id, login_account(self.headers, user))
        if saved["cve"] != "schedule":
            raise Problem(403, "Det här är ingen förfrågan om schemaläggning.")
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 16384:
            raise Problem(413, "För stort eller saknat formulär.")
        data = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        get = lambda key: data.get(key, [""])[0]
        expected = hashlib.sha256(("schedule:"+request_id).encode()).hexdigest()
        if not hmac.compare_digest(get("csrf"), expected):
            raise Problem(403, "Ogiltigt formulär. Öppna en ny länk via /cve schedule.")
        current, candidates, audience = self.schedule_context(saved, user, groups)
        try:
            revision = int(get("revision"))
        except ValueError:
            raise Problem(400, "Ogiltig schemaversion.") from None
        self.store.claim(request_id)
        try:
            if get("action") == "run":
                if not current or revision != current["revision"]:
                    raise Problem(409, "Schemat ändrades. Öppna /cve schedule igen.")
                self.services.scheduled_audience(saved["channel_id"], current["config"]["namespaces"])
                self.schedules.enqueue_now(saved["channel_id"], revision)
                self.scheduler.tick()
                message = "Provkörningen är köad. ACS publicerar rapporten i kanalen när den är klar."
            elif get("action") == "save":
                config = validate_config(data.get("days", []), get("times"), get("timezone"), get("mode"), data.get("namespaces", []))
                if not set(config["namespaces"]) <= set(candidates):
                    raise Problem(403, "Du kan inte lägga till dessa namespaces i kanalens schema.")
                config["sharingPolicy"] = audience["policy"]
                result = self.schedules.save(saved["channel_id"], config, get("enabled") == "yes", saved["mm_user_id"], revision)
                try:
                    self.services.send_callback("", {"kind":"schedule", **result}, shared=True, channel_id=saved["channel_id"])
                    message = "Schemat är sparat. En bekräftelse har skickats till kanalen."
                except Problem:
                    message = "Schemat är sparat, men kanalbekräftelsen kunde inte skickas. Kontrollera inställningarna nedan."
            else:
                raise Problem(400, "Okänd schemaåtgärd.")
            self.store.consume(request_id)
        except Exception:
            self.store.release(request_id)
            raise
        body = "<section><p>"+message+"</p><p><a href='/schedules/"+html.escape(saved["channel_id"])+"'>Visa schema och körningar</a></p>"
        body += "<p><a href='"+html.escape(self.services.mm_public)+"'>Till Mattermost</a>. Kör <code>/cve schedule</code> igen för att ändra eller pausa.</p></section>"
        self.reply(200, page("Teamets schema", body), "text/html; charset=utf-8")

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_args):
        pass  # request IDs and callback URLs are bearer secrets

    def reply(self, status, body, content_type="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for key, value in {"Content-Type": content_type, "Content-Length": str(len(body)),
                           "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                           "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                           "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
                           **(headers or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            path = urlsplit(self.path).path
            if self.public_listener:
                if path == "/healthz":
                    return self.reply(200, {"status": "ok"})
                raise Problem(404, "Sidan hittades inte.")
            user, groups = identity(self.headers, self.services)
            account = login_account(self.headers, user)
            allowed = self.services.allowed_namespaces(user, groups)
            args = parse_qs(urlsplit(self.path).query)
            if path.startswith("/schedules/"):
                channel = path.removeprefix("/schedules/")
                audience = self.services.scheduled_audience(channel, [])
                if not any(self.services.expected_user(member) == account
                           for member in audience["members"] if member != self.services.bot_id):
                    raise Problem(403, "Du är inte verifierad medlem i denna teamkanal.")
                current = self.schedules.get(channel)
                if args.get("format") == ["json"]:
                    return self.reply(200, {"schedule": current, "runs": self.schedules.history(channel)})
                body = "<section><p>"+("Aktiverat" if current and current["enabled"] else "Pausat eller inte konfigurerat")+".</p>"
                if current:
                    cfg = current["config"]
                    body += "<p>"+html.escape(", ".join(DAY_NAMES[d] for d in cfg["days"])+" · "+", ".join(cfg["times"])+" · "+cfg["timezone"])+"</p><p>"+html.escape(", ".join(cfg["namespaces"]))+"</p>"
                body += "<p>Kör <code>/cve schedule</code> i teamkanalen för att ändra eller pausa.</p></section>"+self.schedule_history(channel)
                return self.reply(200, page("Teamets schema och körningar", body), "text/html; charset=utf-8", headers={"Refresh":"15"})
            if path.startswith("/jobs/"):
                job = self.store.get_job(path.removeprefix("/jobs/"), account)
                result = job["result"]
                if result and not set(result["namespaces"]) <= set(allowed):
                    raise Problem(403, "Din namespace-behörighet ändrades. Rapporten är inte längre tillgänglig.")
                if args.get("format") == ["json"]:
                    return self.reply(200, {"state": job["state"], "progress": job["progress"], "result": result, "error": job["error"]})
                if job["state"] == "running":
                    return self.reply(200, page("Imageskanning pågår", "<section><p>"+html.escape(job["progress"])+"</p><p>Sidan uppdateras automatiskt. ACS skickar sammanfattningen till Mattermost när arbetet är klart.</p></section>"), "text/html; charset=utf-8", headers={"Refresh": "4"})
                if job["state"] == "failed":
                    return self.reply(200, page("Skanningen kunde inte slutföras", "<section>"+html.escape(job["error"])+"</section>"), "text/html; charset=utf-8")
                formatted = scan_message(result)
                body = "<section><p><strong>"+html.escape(formatted["attachments"][0]["title"])+"</strong></p><p>Namespaces: "+html.escape(", ".join(result["namespaces"]))+"</p>"
                body += "<p>"+str(len(result["rows"]))+" fynd · "+str(result["scannedImages"])+" skannade images · "+str(result["failedImages"])+" misslyckade.</p>"
                body += "<p>"+str(result["unscannedImages"])+" saknar skanningsunderlag · "+str(result.get("partialImages",0))+" images med varningar.</p>"
                db_title = status_message(result["database"])["attachments"][0]["title"]
                body += "<p>"+html.escape(db_title)+" · "+html.escape(readable_time(result["database"].get("lastUpdated")))+".</p>"
                body += "<p>"+("Sammanfattningen har delats i Mattermost-kanalen." if result["delivery"] == "channel" else "Sammanfattningen har skickats privat till Mattermost.")+"</p>"
                body += "<a href='?format=json'>Läs fullständig JSON-rapport</a></section><p><a href='"+html.escape(self.services.mm_public)+"'>Till Mattermost</a></p>"
                return self.reply(200, page("Imageskanning klar", body), "text/html; charset=utf-8")
            if path == "/":
                options = "".join("<option>"+html.escape(n)+"</option>" for n in allowed)
                body = "<p class='muted'>Inloggad som <strong>"+html.escape(user)+"</strong>. Behörigheter kontrolleras direkt i Kubernetes.</p>"
                body += "<section><h2>Sök en CVE</h2><form action='/search'><input name='cve' placeholder='CVE-2023-0286' required><select name='namespace'><option value=''>Alla mina namespaces</option>"+options+"</select><button>Sök i StackRox</button></form><p>Tillåtna namespaces: "+html.escape(", ".join(allowed) or "inga")+".</p></section>"
                body += "<section><h2>ACS i Mattermost</h2><p><code>/cve status</code> — databasens uppdateringstid.<br><code>/cve scan</code> — beställ nya skanningar av dina godkända images.<br><code>/cve CVE-2022-40897</code> — sök ett specifikt CVE.</p></section>"
                body += "<p><a href='"+html.escape(self.services.mm_public)+"'>Öppna Mattermost</a> · <a href='/oauth2/sign_out'>Logga ut</a></p>"
                return self.reply(200, page("Sårbarheter i dina miljöer", body), "text/html; charset=utf-8")
            if path.startswith("/requests/"):
                request_id = path.removeprefix("/requests/")
                # OIDC owners use verified email; OpenShift owners use the
                # TokenReview identity bound to the approved Mattermost ID map.
                saved = self.store.get(request_id, account)
                cve, namespace = saved["cve"], saved["namespace"]
                if cve == "schedule":
                    return self.schedule_form(request_id, saved, user, groups)
            elif path == "/search":
                saved = None
                cve = validate_cve(args.get("cve", [""])[0])
                namespace = validate_namespace(args.get("namespace", [""])[0])
            else:
                raise Problem(404, "Sidan hittades inte.")
            audience = None
            if saved and saved["shared_requested"]:
                audience = self.services.shared_audience(saved["channel_id"], saved["mm_user_id"], allowed)
                if audience is None:
                    raise Problem(403, "Delning är inte längre aktiverad i kanalen. Kör kommandot igen.")
            selected = select_namespaces(audience["namespaces"] if audience else allowed, namespace)
            if saved:
                self.store.claim(request_id)
            try:
                if cve == "scan":
                    refresh = None
                    if os.getenv("AUTH_PROVIDER", "oidc") == "openshift":
                        token_headers = {"X-Forwarded-Access-Token": self.headers.get("X-Forwarded-Access-Token", "")}
                        refresh = lambda: identity(token_headers, self.services)
                    job_id = self.runner.start(saved, user, groups, selected, audience, refresh)
                    self.store.consume(request_id)
                    return self.reply(303, "", headers={"Location": "/jobs/"+job_id})
                result = self.services.database_status() if cve == "status" else self.services.lookup(cve, selected)
                if saved:
                    if os.getenv("AUTH_PROVIDER", "oidc") == "openshift":
                        fresh_user, groups = identity(self.headers, self.services)
                        if fresh_user != user or not set(selected) <= set(self.services.allowed_namespaces(user, groups)):
                            raise Problem(403, "Inloggningen eller namespace-behörigheten ändrades. Inga fynd delades.")
                    if audience:
                        # A slow scan lookup must not publish to an audience or
                        # grant set that changed while it was in progress.
                        fresh_allowed = self.services.allowed_namespaces(user, groups)
                        fresh = self.services.shared_audience(saved["channel_id"], saved["mm_user_id"], fresh_allowed)
                        if (not fresh or fresh["members"] != audience["members"] or fresh.get("policy") != audience.get("policy")
                                or not set(selected) <= set(fresh["namespaces"])):
                            raise Problem(403, "Kanalens medlemmar eller behörigheter ändrades. Kör kommandot igen; inga fynd delades.")
                    result["sharingPolicy"] = audience.get("policy", "common") if audience else "private"
                    self.services.send_callback(saved["callback"], result, shared=bool(audience), channel_id=saved["channel_id"])
                    self.store.consume(request_id)
            except Exception:
                if saved:
                    self.store.release(request_id)
                raise
            if cve == "status":
                formatted = status_message(result)
                card = formatted["attachments"][0]
                body = "<section><h2>"+html.escape(card["title"])+"</h2><p>"+html.escape(card["text"])+"</p>"
                for item in card["fields"]:
                    body += "<p><strong>"+html.escape(item["title"])+":</strong> "+html.escape(item["value"])+"</p>"
                body += "</section><p>Status har skickats till Mattermost.</p><a href='/'>Till startsidan</a>"
                return self.reply(200, page("CVE-databas", body), "text/html; charset=utf-8")
            LOG.info("lookup user=%s namespaces=%s matches=%d", user, ",".join(selected), len(result["rows"]))
            body = "<p>Resultat för "+html.escape(user)+" i "+html.escape(", ".join(selected))+".</p>"
            body += "<section><p><strong>"+str(len(result["rows"]))+" fynd</strong> · "+str(result["scannedImages"])+" skannade images · "+str(result["unscannedImages"])+" ej färdigskannade.</p>"
            body += "<div style='overflow:auto'><table><tr><th>Namespace / app</th><th>Paket</th><th>Version</th><th>Åtgärdad i</th><th>CVSS</th></tr>"
            for row in result["rows"]:
                body += "<tr>"+"".join("<td>"+html.escape(str(x))+"</td>" for x in [row["namespace"]+" / "+row["deployment"], row["component"], row["version"], row["fixedBy"] or "Ej angivet", row["cvss"]])+"</tr>"
            body += "</table></div><p class='muted'>Ett tomt resultat är inte ett bevis på att miljön är fri från sårbarheter. Saknade skanningar och ej stödda operativsystem kan ge ofullständiga resultat.</p></section>"
            if saved:
                body += "<p>" + ("Resultatet har delats i Mattermost-kanalen." if audience else "Svaret har också skickats privat till Mattermost.") + "</p>"
            body += "<a href='/'>Ny sökning</a>"
            self.reply(200, page(cve, body), "text/html; charset=utf-8")
        except (Problem, ScheduleError) as exc:
            self.reply(exc.status, page("Förfrågan kunde inte slutföras", "<section>"+html.escape(exc.message)+"</section><a href='/'>Till startsidan</a>"), "text/html; charset=utf-8")
        except Exception:
            LOG.exception("request_failed")
            self.reply(500, {"error": "Ett internt fel inträffade. Inga fynd lämnades ut."})

    def do_POST(self):
        verified_command = False
        try:
            dialog = re.fullmatch(r"/slash/cve/dialog/([A-Za-z0-9_-]{43})", urlsplit(self.path).path)
            if self.public_listener and dialog:
                return self.native_schedule_post(dialog.group(1))
            if not self.public_listener and re.fullmatch(r"/requests/[A-Za-z0-9_-]+/schedule", urlsplit(self.path).path):
                return self.schedule_post()
            if not self.public_listener or urlsplit(self.path).path != "/slash/cve":
                raise Problem(404, "Sidan hittades inte.")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise Problem(413, "Beställningen saknas eller är för stor.")
            data = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
            get = lambda key: data.get(key, [""])[0]
            command = get("command") or "/cve"
            if command not in ["/acs", "/cve"]:
                raise Problem(400, "Okänt kommando. Kör /cve help för hjälp.")
            token_key = "SLASH_ACS_TOKEN" if command == "/acs" else "SLASH_TOKEN"
            verify_command_token(os.environ.get(token_key, ""), self.headers.get("Authorization", ""), get("token"))
            verified_command = True
            fields = get("text").split()
            if not fields or fields == ["help"] or fields == ["hjälp"]:
                return self.reply(200, self.services.command_reply(**help_message()))
            if not 1 <= len(fields) <= 2:
                raise Problem(400, "Kör /cve help för tillgängliga kommandon.")
            cve = fields[0].lower() if fields[0].lower() in {"scan", "status", "schedule"} else validate_cve(fields[0])
            if cve in {"status", "schedule"} and len(fields) != 1:
                raise Problem(400, "Kör /cve "+cve+" utan extra argument.")
            namespace = validate_namespace(fields[1] if len(fields) == 2 else "")
            callback = self.services.callback_path(get("response_url"))
            email = self.services.expected_user(get("user_id"))
            channel_id = get("channel_id")
            if not re.fullmatch(r"[a-z0-9]{26}", channel_id):
                raise Problem(400, "Mattermost-kanalen kunde inte identifieras.")
            shared = channel_id in self.services.channel_scopes
            if cve == "schedule" and channel_id not in self.services.schedule_scopes:
                raise Problem(403, "Automatik är inte godkänd för denna kanal. Be plattformsteamet ansluta kanalen först.")
            if cve == "schedule":
                self.native_schedules.open(get("user_id"), channel_id, get("trigger_id"))
                return self.reply(200, self.services.command_reply("**ACS · Teamets schema**\nFormuläret öppnas här i Mattermost. Kör /cve schedule igen för att ändra, pausa eller provköra."))
            request_id = self.store.create(email, cve, namespace, callback, channel_id, get("user_id"), shared=shared)
            link = self.services.public + "/requests/" + request_id
            policy = self.services.channel_policies.get(channel_id, "common")
            self.reply(200, self.services.command_reply(**request_message(link, cve, namespace, shared, policy)))
        except (Problem, ScheduleError) as exc:
            if self.public_listener:
                # Mattermost displays command response cards only on HTTP 200.
                # Authentication failures still retain their rejection status.
                self.reply(200 if verified_command else exc.status, self.services.command_reply(**error_message(exc.message)))
            else:
                self.reply(exc.status, page("Schemat kunde inte ändras", "<section>"+html.escape(exc.message)+"</section>"), "text/html; charset=utf-8")
        except (ValueError, UnicodeDecodeError):
            self.reply(200 if verified_command else 400, self.services.command_reply(**error_message("Beställningen kunde inte läsas.")))
        except Exception:
            LOG.exception("slash_failed")
            self.reply(200 if verified_command else 500, self.services.command_reply(**error_message("Ett internt fel inträffade. Försök igen senare.")))


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    services = Services()
    store = Store(os.getenv("DATABASE_PATH", "/data/requests.sqlite3"))
    services.alerts = CveAlerts(store)
    Handler.services, Handler.store = services, store
    Handler.runner = ScanRunner(services, store)
    Handler.schedules = Schedules(store)
    Handler.scheduler = Scheduler(services, Handler.schedules, Handler.runner)
    Handler.native_schedules = NativeSchedules(services, store, Handler.schedules, Handler.scheduler)
    public = type("WebhookHandler", (Handler,), {"public_listener": True})
    ui = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    webhook = ThreadingHTTPServer(("0.0.0.0", 8001), public)
    for server in [ui, webhook]:
        server.daemon_threads = True
    threading.Thread(target=ui.serve_forever, daemon=True).start()
    threading.Thread(target=Handler.scheduler.loop, daemon=True).start()
    LOG.info("started browser=loopback:8000 webhook=:8001")
    webhook.serve_forever()


if __name__ == "__main__":
    main()
