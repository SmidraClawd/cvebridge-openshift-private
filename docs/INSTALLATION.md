# Installation i ditt labb

Följ kommandona i [README](../README.md). På datorn behöver du Docker eller
Podman, `oc` och nätverksåtkomst till labbet. Go behöver inte installeras lokalt.

## Förutsättningar en gång

- Mattermost och ACS Central fungerar redan. Boten når deras adresser.
- Botens namespace och en skrivbar PVC finns. Ange dem i `.env`.
- Ditt OpenShift-konto får pusha images till det projektet.
- Plattformsteamet godkänner botens Kubernetes-behörigheter via bootstrap.

[De 11 fälten](ENV_VARDEN.md) kopplar boten till era befintliga system.
Imagen innehåller programmet; företagets adresser och tokens byggs inte in.

## Mattermost ställs in en gång

Skapa ett botkonto med rollen **Member** och bjud in det till rapportkanalen.
Registrera ett slash-kommando via **Integrations → Slash Commands**:

| Fält | Värde |
| --- | --- |
| Command Trigger Word | `cve` |
| Request Method | `POST` |
| Request URL | `http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve` |

Byt `DITT_NAMESPACE`. Samma Request URL skrivs ut av installationsskriptet.
Kopiera botens token och slash-kommandots token till deras fält i `.env`.
Mattermost-servern måste kunna nå botens interna Service och formulärens callbacks.
Om interna integrationer blockeras behöver Mattermost-admin godkänna just botens
servicevärd i `AllowedUntrustedInternalConnections`.

## Bygg, tagga och pusha

```sh
docker build -t cvebridge:local .
oc login
oc project DITT_NAMESPACE
./cvebridge.sh push
```

Bygget fungerar utan `.env` och utan klusterinloggning. Du kan även använda
`./cvebridge.sh build` för samma lokala bygge. För Podman: använd `podman build`
och sätt `CONTAINER_ENGINE=podman` när du kör skriptet.

`push` kontrollerar projektet och PVC:n, genererar YAML, hittar registry-routen,
loggar in med din oc-token via stdin, taggar `cvebridge:local` och pushar.
Ingen installation görs automatiskt. Namespace, image och PVC kommer från ditt
valda upplägg; taggen utgår från det lokala image-ID:t.

Deployment använder alltid den interna adressen i standardflödet:
`image-registry.openshift-image-registry.svc:5000/NAMESPACE/cvebridge:TAGG`.
Push från datorn använder registryts nåbara route. Om routen inte kan läsas eller
byggmiljön når intern DNS kan `REGISTRY_PUSH_HOST` anges enligt
[de valfria inställningarna](env-options.example). Docker/Podman behöver lita på
registryts TLS-certifikat.

## Applicera YAML

| Fil | Vem applicerar / vad den gör |
| --- | --- |
| `deploy/bootstrap.yaml` | Plattformsteamet, en gång: SubjectAccessReview och reporterbehörighet. |
| `deploy/app/deployment.yaml` | Du: en botreplika med image och PVC-montering. |
| `deploy/app/service.yaml` | Du: intern Service på port 8001. |
| `deploy/app/configmap.yaml` | Du: appinställningar. |
| `deploy/app/secret.yaml` | Du: Mattermost- och ACS-token. |
| `deploy/app/serviceaccounts.yaml` | Du: botens och reporterns servicekonton. |

```sh
oc apply -f deploy/bootstrap.yaml
oc apply -f deploy/app/
oc rollout status deployment/cvebridge -n DITT_NAMESPACE
```

Bootstrap kräver plattformsbehörighet. `app/` innehåller inga klustergemensamma
roller. Er färdiga PVC ändras inte. [PVC-guiden](NATVERKSLAGRING.md) beskriver
lagringskopplingen. Filerna innehåller företagsvärden och ska behållas lokalt.

## Kontrollera boten

Skriv i rapportkanalen:

```text
/cve help
/cve status
/cve scan team-a
/cve schedule
```

Byt skanningsnamespace. Kontrollera rapporten, Åtgärd-raderna och schemaformuläret.
Vid fel: `oc logs deployment/cvebridge -n DITT_NAMESPACE -c bot --tail=50`.
`/healthz` kontrollerar processen; en riktig skanning verifierar anslutningarna.

## Uppdatera senare

Bygg igen och kör `./cvebridge.sh push`, sedan `oc apply -f deploy/app/`.
En ny byggd image får en ny automatisk tagg. Om bara `.env` ändras kör du
`./cvebridge.sh render`, applicerar `app/` och startar om Deployment eftersom
miljövariabler läses vid processstart. Låt PVC:n vara kvar.

Källor: [OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry),
[Mattermost slash-kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom).
