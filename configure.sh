#!/usr/bin/env bash
# Ubuntu/Linux. Only prepares local files; build, push and oc apply are manual.
set -euo pipefail
command -v python3 >/dev/null || { echo 'Python 3 saknas. Installera python3 i Ubuntu.' >&2; exit 1; }
CVE_SETUP_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 -c "$(cat <<'PY'
import argparse
import getpass
import json
import os
import re
import secrets
import shlex
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(sys.argv.pop(1))
LOCAL = ROOT / '.local'
STATE = LOCAL / 'setup.json'
DEPLOY = ROOT / 'deploy'
DEFAULT_REGISTRY = 'image-registry.openshift-image-registry.svc:5000'
IMAGE_PROJECT = 'image-security'
FILES = ('configmap.yaml', 'secret.yaml', 'deployment.yaml', 'z-deployment.yaml', 'service.yaml',
         'serviceaccount.yaml', 'trusted-ca.yaml', 'route.yaml', 'image-puller.yaml')
FIELDS = (
    ('namespace', 'Namespace för boten', 'image-security', False),
    ('pvc', 'Namnet på din befintliga PVC', '', False),
    ('namespaces', 'Projekt att skanna, separerade med komma, eller * för hela ACS-klustret', '', False),
    ('acs_url', 'ACS Central-adress, https://...', '', False),
    ('cluster_id', 'Kluster-ID i ACS, från labbklustrets detaljsida', '', False),
    ('acs_token', 'ACS API-token', '', True),
    ('mm_url', 'Mattermost-adress, https://...', '', False),
    ('channel_id', 'Driftkanalens ID, 26 tecken', '', False),
    ('bot_token', 'Mattermost-botens Access Token', '', True),
    ('command_token', 'Token för /cve, kan fyllas i senare', '', True),
    ('route_host', 'Botens Route-värdnamn, utan https://, kan fyllas i senare', '', False),
)
CORE = {key for key, _, _, _ in FIELDS} - {'command_token', 'route_host'}
NAMES = {key: label.split(',')[0] for key, label, _, _ in FIELDS}

def valid_name(value, max_length=63):
    return len(value) <= max_length and re.fullmatch(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?', value)

def normalize(key, value):
    value = value.strip()
    if not value:
        return ''
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Värdet innehåller kontrolltecken.')
    if key == 'namespace':
        if not valid_name(value) or value in ('default', 'kube-system') or value.startswith('openshift-'):
            raise ValueError('Ange ett eget OpenShift-projektnamn, exempelvis image-security.')
    elif key == 'pvc':
        if len(value) > 253 or not all(valid_name(part) for part in value.split('.')):
            raise ValueError('Ange PVC-namnet från oc get pvc, inte en nätverkssökväg.')
    elif key == 'namespaces':
        names = sorted(set(part.strip() for part in value.split(',')))
        if value != '*' and (len(names) > 100 or not all(valid_name(part) for part in names)):
            raise ValueError('Ange projektnamn med komma mellan, exempelvis team-a,team-b, eller endast * för hela ACS-klustret.')
        value = ','.join(names)
    elif key in ('acs_url', 'mm_url'):
        u = urlsplit(value)
        if (u.scheme != 'https' or not u.hostname or u.username or u.password
                or u.path not in ('', '/') or u.query or u.fragment or u.port == 0):
            raise ValueError('Ange bara HTTPS-serveradressen, exempelvis https://central.foretaget.se.')
        value = value.rstrip('/')
    elif key == 'cluster_id':
        if not re.fullmatch(r'[A-Za-z0-9-]+', value):
            raise ValueError('Ange ACS kluster-ID, inte namn eller adress.')
    elif key == 'channel_id':
        if not re.fullmatch(r'[a-z0-9]{26}', value):
            raise ValueError('Kanalens ID ska vara 26 små bokstäver/siffror, från Visa info i Mattermost.')
    elif key == 'route_host':
        if value.startswith('https://'):
            u = urlsplit(value)
            if u.path not in ('', '/') or u.query or u.fragment or u.username or u.password:
                raise ValueError('Ange värdnamnet utan sökväg.')
            value = u.netloc
        value = value.lower()
        if len(value) > 253 or '.' not in value or not all(valid_name(part) for part in value.split('.')):
            raise ValueError('Ange ett Route-värdnamn, exempelvis cvebridge.apps.labb.foretaget.se.')
    return value

def registry(value):
    # REGISTRY is a host[:port], never a URL, image path or shell expression.
    value = value.strip().lower()
    u = urlsplit('//' + value)
    if (not u.hostname or u.username is not None or u.password is not None
            or u.path or u.query or u.fragment or u.port == 0
            or not all(valid_name(part) for part in u.hostname.split('.'))):
        raise ValueError('REGISTRY ska vara ett värdnamn med eventuell port, utan https:// eller imagesökväg.')
    return value

def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        try:
            os.fchmod(f.fileno(), 0o600)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)

def yaml(value, level=0):
    # JSON-quoted strings are valid YAML scalars. User input is never shell code.
    pad = '  ' * level
    if isinstance(value, dict):
        if not value:
            return pad + '{}\n'
        result = ''
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                result += pad + str(key) + ':\n' + yaml(item, level + 1)
            else:
                result += pad + str(key) + ': ' + json.dumps(item, ensure_ascii=False) + '\n'
        return result
    if isinstance(value, list):
        result = ''
        for item in value:
            if isinstance(item, (dict, list)) and item:
                result += pad + '-\n' + yaml(item, level + 1)
            else:
                result += pad + '- ' + json.dumps(item, ensure_ascii=False) + '\n'
        return result
    return pad + json.dumps(value, ensure_ascii=False) + '\n'

def resource(kind, name, namespace, **extra):
    versions = {'Deployment': 'apps/v1', 'Route': 'route.openshift.io/v1',
                'RoleBinding': 'rbac.authorization.k8s.io/v1'}
    return {'apiVersion': versions.get(kind, 'v1'), 'kind': kind,
            'metadata': {'name': name, 'namespace': namespace}, **extra}

def image(settings):
    return f'{settings["registry"]}/{IMAGE_PROJECT}/cvebridge:{settings["tag"]}'

def manifests(s):
    ns = s['namespace']
    config = {
        'ACCESS_MODE': 'operations', 'SCAN_NAMESPACES': s['namespaces'],
        'MATTERMOST_INTERNAL_URL': s['mm_url'], 'STACKROX_URL': s['acs_url'],
        'STACKROX_CLUSTER_ID': s['cluster_id'], 'MATTERMOST_CHANNEL_ID': s['channel_id'],
        'MATTERMOST_DIALOG_URL': f'https://{s["route_host"]}/slash/cve/dialog' if s['route_host'] else '',
        'DATABASE_MONITOR_CHANNEL_ID': s['channel_id'], 'DATABASE_MAX_AGE_HOURS': '24',
        'SENSOR_MONITOR_ENABLED': 'true',
        'LISTEN_ADDR': ':8001', 'STATE_FILE': '/data/requests.sqlite3',
        'MATTERMOST_CA_FILE': '/ca/ca-bundle.crt', 'STACKROX_CA_FILE': '/ca/ca-bundle.crt',
        'STACKROX_SCANNER_COMPONENT': 'SCANNER_V4', 'SCHEDULE_DEFAULT_TIMEZONE': 'Europe/Stockholm',
        'CVE_ALERTS_ENABLED': 'true', 'CVE_ALERT_MIN_CVSS': '9', 'CVE_ALERT_FIRST_REPORT': 'false',
    }
    labels = {'app.kubernetes.io/name': 'cvebridge'}
    container = {
        'name': 'bot', 'image': image(s), 'imagePullPolicy': 'Always',
        'ports': [{'name': 'webhook', 'containerPort': 8001}],
        'envFrom': [{'configMapRef': {'name': 'cvebridge-config'}}, {'secretRef': {'name': 'cvebridge-tokens'}}],
        'env': [{'name': 'NAMESPACE', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.namespace'}}}],
        'volumeMounts': [{'name': 'data', 'mountPath': '/data'}, {'name': 'trusted-ca', 'mountPath': '/ca', 'readOnly': True}],
        'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
        'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '1', 'memory': '512Mi'}},
    }
    for probe in ('startupProbe', 'readinessProbe', 'livenessProbe'):
        container[probe] = {'httpGet': {'path': '/healthz', 'port': 'webhook'}, 'periodSeconds': 10, 'failureThreshold': 6}
    pod = {
        'serviceAccountName': 'cvebridge', 'automountServiceAccountToken': False,
        'terminationGracePeriodSeconds': 30,
        'securityContext': {'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'containers': [container],
        'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': s['pvc']}},
                    {'name': 'trusted-ca', 'configMap': {'name': 'cvebridge-trusted-ca', 'items': [{'key': 'ca-bundle.crt', 'path': 'ca-bundle.crt'}]}}],
    }
    result = {
        'configmap.yaml': resource('ConfigMap', 'cvebridge-config', ns, data=config),
        'secret.yaml': resource('Secret', 'cvebridge-tokens', ns, type='Opaque', stringData={
            'MATTERMOST_BOT_TOKEN': s['bot_token'], 'MATTERMOST_COMMAND_TOKEN': s['command_token'], 'STACKROX_TOKEN': s['acs_token']}),
        'serviceaccount.yaml': resource('ServiceAccount', 'cvebridge', ns, automountServiceAccountToken=False),
        'z-deployment.yaml': resource('Deployment', 'cvebridge', ns, spec={
            'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': labels},
            'template': {'metadata': {'labels': labels, 'annotations': {'cvebridge/setup-revision': s.get('revision', 'initial')}}, 'spec': pod}}),
        'service.yaml': resource('Service', 'cvebridge-webhook', ns, spec={
            'selector': labels, 'ports': [{'name': 'webhook', 'port': 8001, 'targetPort': 'webhook'}]}),
        'trusted-ca.yaml': resource('ConfigMap', 'cvebridge-trusted-ca', ns, data={}),
    }
    result['trusted-ca.yaml']['metadata']['labels'] = {'config.openshift.io/inject-trusted-cabundle': 'true'}
    if s['route_host']:
        result['route.yaml'] = resource('Route', 'cvebridge-webhook', ns, spec={
            'host': s['route_host'], 'path': '/slash/cve', 'to': {'kind': 'Service', 'name': 'cvebridge-webhook'},
            'port': {'targetPort': 'webhook'}, 'tls': {'termination': 'edge', 'insecureEdgeTerminationPolicy': 'Redirect'}})
    if ns != IMAGE_PROJECT:
        result['image-puller.yaml'] = resource('RoleBinding', f'cvebridge-pull-{ns}', IMAGE_PROJECT,
            roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'system:image-puller'},
            subjects=[{'kind': 'ServiceAccount', 'name': 'cvebridge', 'namespace': ns}])
    return result

def status(s):
    missing = [NAMES[key] for key, _, _, _ in FIELDS if key in CORE and not s.get(key)]
    pending = []
    if not s.get('command_token'):
        pending.append('Token för /cve saknas: kommandon väntar tills du skapat kommandot i Mattermost.')
    if not s.get('route_host'):
        pending.append('Route-värdnamn saknas: ingen Route skapas och schemaformuläret väntar på sin adress.')
    if missing:
        print('\nUTKAST SPARAT. YAML-filer för installation har inte skapats.')
        print('Fyll i senare genom att köra ./configure.sh igen:')
        for field in missing:
            print('  - ' + field)
    else:
        print('\nBOTEN ÄR KLAR ATT INSTALLERA. Färdiga YAML-filer finns i deploy/.')
        if not pending:
            print('Även /cve och schemaformuläret är konfigurerade.')
    for line in pending:
        print(line)
    return not missing

def commands(s, ready):
    print('\nKör själv i projektmappen, efter din vanliga oc login:')
    print('Podman bygger Go-koden och imagen från källkod + vendor. Ingen separat Go-byggning behövs.')
    print('Första gången kan Go-byggimagen behöva hämtas; själva kompileringen körs utan nätverk.')
    print('REGISTRY=' + shlex.quote(s['registry']))
    print('podman build --network=none --platform linux/amd64 -f Dockerfile -t localhost/cvebridge:latest .')
    print('podman tag localhost/cvebridge:latest "$REGISTRY/' + IMAGE_PROJECT + '/cvebridge:latest"')
    print('oc whoami -t | podman login "$REGISTRY" --username cvebridge --password-stdin')
    print('podman push "$REGISTRY/' + IMAGE_PROJECT + '/cvebridge:latest"')
    if ready:
        print('oc apply -f deploy/')
        print('oc rollout status deployment/cvebridge -n ' + shlex.quote(s['namespace']))
    else:
        print('Bygget kan köras redan nu. Fyll utkastet innan du applicerar YAML.')
    print('\nUbuntu-maskinen behöver nå registryts interna DNS/adress och lita på dess CA.')
    if ready and s['route_host']:
        print('Mattermost /cve: POST https://' + s['route_host'] + '/slash/cve')
    if ready and s['namespace'] != IMAGE_PROJECT:
        print('image-puller.yaml ger botens namespace rätt att dra imagen från image-security; apply behöver rätt att skapa bindningen där.')

def main():
    parser = argparse.ArgumentParser(prog='./configure.sh', description='Förbered CVEBridge lokalt. Bygg, push och apply kör du själv.')
    options = parser.add_mutually_exclusive_group()
    options.add_argument('--check', action='store_true', help='Visa vad som saknas, utan att ändra filer.')
    options.add_argument('--update-image', '--new-tag', dest='update_image', action='store_true', help='Förbered omstart vid apply för en ny image med samma :latest-tagg.')
    options.add_argument('--edit', action='store_true', help='Ändra sparade uppgifter. Utan flagga frågas bara tomma fält.')
    args = parser.parse_args()
    if LOCAL.is_symlink() or DEPLOY.is_symlink():
        raise ValueError('Konfigurationsmapparna får inte vara symboliska länkar.')
    if args.check and not STATE.exists():
        print('Inga svar har sparats ännu. Kör ./configure.sh först.')
        return 1
    s = {}
    if STATE.exists():
        if STATE.is_symlink():
            raise ValueError('Utkastet får inte vara en symbolisk länk.')
        try:
            s = json.loads(STATE.read_text(encoding='utf-8'))
            if not isinstance(s, dict):
                raise ValueError()
        except (ValueError, OSError):
            raise ValueError('Det sparade utkastet kunde inte läsas. Filen har inte skrivits över.')
    existing = bool(s)
    try:
        s['registry'] = registry(os.environ.get('REGISTRY', s.get('registry', DEFAULT_REGISTRY)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Ogiltig REGISTRY. Ange värdnamn och eventuell port, utan https:// eller imagesökväg. Inga filer har ändrats.')
    for key, _, default, _ in FIELDS:
        try:
            s[key] = normalize(key, s.get(key, default))
        except (ValueError, TypeError, AttributeError):
            raise ValueError('Ogiltigt sparat värde för ' + NAMES[key] + '. Utkastet har inte skrivits över.')
    if 'tag' in s and not isinstance(s['tag'], str):
        raise ValueError('Utkastets imagetagg är ogiltig. Filen har inte skrivits över.')
    if 'tag' in s and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', s['tag']):
        raise ValueError('Utkastets imagetagg är ogiltig. Filen har inte skrivits över.')
    if 'revision' in s and (not isinstance(s['revision'], str) or not re.fullmatch(r'[a-f0-9]{32}', s['revision'])):
        raise ValueError('Utkastets konfigurationsrevision är ogiltig. Filen har inte skrivits över.')
    # Migrate existing saved versions to the fixed tag without changing answers.
    s['tag'] = 'latest'
    if args.check:
        ready = status(s)
        if ready:
            for filename, obj in manifests(s).items():
                path = DEPLOY / filename
                expected = '# Genererad av configure.sh. Kör skriptet igen för ändringar.\n' + yaml(obj)
                if path.is_symlink() or not path.exists() or path.read_text(encoding='utf-8') != expected:
                    print('YAML-filerna behöver uppdateras. Kör ./configure.sh igen.')
                    return 1
        return 0 if ready else 1
    print('CVEBridge · lokal konfiguration')
    print('Enter = behåll värde eller lämna tomt. Använd --edit för att ändra sparade svar; där rensar - ett värde.')
    print('Registry: ' + s['registry'] + '/' + IMAGE_PROJECT + '/cvebridge')
    print('Namespace och befintlig PVC ska redan finnas i OpenShift.\n')
    if existing and not args.edit:
        print('Sparade värden återanvänds. Bara tomma fält efterfrågas.')
        if all(s[key] for key, _, _, _ in FIELDS):
            print('Alla uppgifter finns redan. Inga frågor behövs.')
    previous = [s[key] for key, _, _, _ in FIELDS]
    for key, label, _, sensitive in FIELDS:
        current = s.get(key, '')
        if existing and current and not args.edit:
            continue
        hint = ' [sparad]' if sensitive and current else (' [' + current + ']' if current else '')
        while True:
            prompt = label + hint + ': '
            answer = getpass.getpass(prompt) if sensitive and sys.stdin.isatty() else input(prompt)
            try:
                s[key] = normalize(key, '' if answer.strip() == '-' else (answer if answer.strip() else current))
                break
            except ValueError as err:
                print(str(err))
    if LOCAL.is_symlink() or DEPLOY.is_symlink():
        raise ValueError('Konfigurationsmapparna får inte vara symboliska länkar.')
    if not s.get('revision') or previous != [s[key] for key, _, _, _ in FIELDS] or args.update_image:
        # An opaque revision triggers rollout without publishing a secret hash.
        s['revision'] = secrets.token_hex(16)
    LOCAL.mkdir(exist_ok=True, mode=0o700)
    LOCAL.chmod(0o700)
    write_private(STATE, json.dumps(s, ensure_ascii=False, indent=2) + '\n')
    ready = all(s.get(key) for key in CORE)
    DEPLOY.mkdir(exist_ok=True)
    rendered = manifests(s) if ready else {}
    for filename in FILES:
        path = DEPLOY / filename
        if filename in rendered:
            text = '# Genererad av configure.sh. Kör skriptet igen för ändringar.\n' + yaml(rendered[filename])
            if path.is_symlink() or not path.exists() or path.read_text(encoding='utf-8') != text:
                write_private(path, text)
            else:
                path.chmod(0o600)
        elif path.exists() or path.is_symlink():
            path.unlink()
    status(s)
    commands(s, ready)
    return 0

try:
    sys.exit(main())
except (EOFError, KeyboardInterrupt):
    print('\nAvbrutet. Tidigare sparade filer behålls.', file=sys.stderr)
    sys.exit(1)
except (ValueError, OSError) as err:
    print('Konfigurationen kunde inte sparas: ' + str(err), file=sys.stderr)
    sys.exit(1)
PY
)" "$CVE_SETUP_ROOT" "$@"
