# CVEBridge · driftbot för Mattermost

Status, imageskanning, CVE-rapporter och schemaformulär i en privat driftkanal.
Boten frågar ACS Central direkt. Driftmedlemmarna behöver inga personliga
OpenShift-konton eller användarmappningar. Scheman och larmstatus sparas på PVC.

```text
./configure.sh → svara på frågor → bygg/tagga/pusha med Podman → oc apply -f deploy/
```

## Förbered

Ubuntu/Linux med **Bash, Python 3, Podman och `oc`**. Projektet och en befintlig
PVC ska finnas i OpenShift. Standardprojektet är **`image-security`**; PVC:n
måste finnas i samma projekt som boten.

Registryadressen är fast i detta flöde:

```text
image-registry.openshift-image-registry.svc:5000/image-security/cvebridge:<automatisk-tagg>
```

Ubuntu-maskinen måste kunna nå denna interna DNS/adress och lita på registryts
CA. Det här flödet använder samma interna adress för taggning, push och Deployment.
En vanlig dator utanför klustrets nät kan behöva nätverks-/DNS-åtkomst ordnad av
plattformsteamet för att nå just den adressen.

## 1. Fyll i genom skriptet

Kör från projektmappen:

```sh
./configure.sh
```

Skriptet frågar efter namespace, PVC, projektlista, ACS, Mattermost och tokens.
Det skapar samma imagetagg i alla kommandon och Deployment. Formuläradressen
räknas ut från botens Route-värdnamn.

| Fråga | Var du hittar värdet |
| --- | --- |
| Namespace | OpenShift-projektet där boten och PVC:n finns. Enter väljer `image-security`. |
| PVC | `oc get pvc -n image-security` → kopiera **NAME** för er befintliga lagring. |
| Projekt att skanna | OpenShift-projektnamn, exempelvis `team-a,team-b`. Boten skannar aktiva images som ACS känner till där. |
| ACS-adress | Adressen till Central där du loggar in, exempelvis `https://central.foretaget.se`. |
| Kluster-ID i ACS | **Platform Configuration → Clusters → labbklustret**. Kopiera ID:t efter `/main/clusters/` i adressfältet. |
| ACS API-token | **Platform Configuration → Integrations → API Token**. ACS-ansvarig väljer roll och access scope. |
| Mattermost-adress | Serveradressen, exempelvis `https://mattermost.foretaget.se`, utan kanalens sökväg. |
| Driftkanalens ID | Privat kanal → **Visa info / View Info (i)** → **ID**, 26 tecken. Bjud in boten. |
| Botens Access Token | **Integrations → Bot Accounts** → skapa ett botkonto med rollen **Member** → kopiera **Access Token**. |
| Token för `/cve` | **Integrations → Slash Commands → Add**. Trigger `cve`, metod `POST`, Request URL `https://BOTENS_ROUTE/slash/cve`. **Save** → **Token**. |
| Route-värdnamn | Botens godkända DNS-namn, exempelvis `cvebridge.apps.labb.foretaget.se`. Skriptet skapar routen och lägger till `/slash/cve/dialog` i ConfigMap. |

ACS-tokenen behöver **Read** på Deployment, Image, Cluster, Namespace och
Administration samt **Write** på Image. ACS-ansvarig godkänner rättigheterna.

**Tomma svar:** Enter behåller ett sparat värde; ett nytt tomt fält lämnas till
senare. Skriv `-` för att rensa ett tidigare svar. Tokens visas aldrig i terminalen.

Saknas obligatoriska uppgifter sparas ett **utkast** och inga installations-YAML
skapas. Du kan ändå bygga imagen. Saknas bara `/cve`-token eller Route kan boten
starta och skicka databasstatus, men kommandon respektive externa formulär väntar.
Kör skriptet igen för att komplettera:

```sh
./configure.sh
./configure.sh --check
```

Svar, inklusive tokens, sparas lokalt i `.local/setup.json`. Den filen och
alla genererade YAML-filer är git-ignorerade och får filrättighet `0600`.
Det finns ingen `.env`-fil i installationsflödet. Har du fyllt gamla YAML-filer
från en tidigare version, behåll en lokal kopia av dem tills du matat in svaren.

## 2. Bygg, tagga och pusha själv

Logga in med ert vanliga `oc login`-kommando. Kopiera sedan de **exakta kommandon
som skriptet visar** för:

1. `podman build` — bygger imagen lokalt.
2. `podman tag` — använder den fasta registryadressen och automatisk tagg.
3. `oc whoami -t | podman login ... --password-stdin` — loggar in i registryt.
4. `podman push` — skickar imagen till `image-security`.

Skriptet bygger, pushar eller applicerar inget åt dig. Företagsinställningar och
tokens byggs inte in i imagen.

## 3. Starta med en enda apply

När skriptet säger att boten är klar att installera, och imagen är pushad:

```sh
oc apply -f deploy/
oc rollout status deployment/cvebridge -n image-security
oc logs deployment/cvebridge -n image-security -c bot --tail=50
```

Byt namespace i kontrollkommandona om du valde ett annat. Alla YAML-filer har
redan rätt namespace. `deploy/` innehåller ConfigMap, Secret, Deployment,
ServiceAccount, Service, CA-ConfigMap och Route när ett Route-värdnamn är angivet.
Deployment heter `z-deployment.yaml` så ConfigMap och Secret appliceras före omstarten.
Väljer du annat botnamespace än `image-security` skapas även `image-puller.yaml`;
kontot som kör apply behöver då rätt att ge image-pull-åtkomst i `image-security`.

OpenShift fyller den separata `cvebridge-trusted-ca` med klustrets betrodda
CA-paket. Det monteras på `/ca/ca-bundle.crt`; imagen innehåller inga CA-filer.
CA:n som utfärdat Mattermosts och ACS certifikat måste ingå i klusterpaketet.
`oc get configmap cvebridge-trusted-ca -n image-security` ska visa `DATA: 1`.
Botens ServiceAccount behöver ingen Kubernetes-API-token eller personlig RBAC.

Testa i driftkanalen när `/cve` är registrerat och boten är inbjuden:

```text
/cve status
/cve scan team-a
/cve report team-a
/cve schedule
```

Byt `team-a` mot ett projekt du angav. Alla kanalmedlemmar kan köra kommandon
för projektlistan och ändra kanalens schema. Boten verifierar token, privat kanal,
medlemskap och TLS. Daglig status för CVE-databasens ålder och larm vid ändrat
läge går till samma driftkanal. Första kompletta CVE-rapporten skapar normalt ett
utgångsläge utan akut ping; nya kritiska fynd kan sedan ge en engångsping.

## Ändringar senare

**Bara nya inställningar eller tokens:** kör `./configure.sh` igen, behåll taggen,
och kör sedan:

```sh
oc apply -f deploy/
```

Skriptet markerar ändringen i Deployment så poden startas om automatiskt vid apply.
Ingen ny image behövs. När enbart klustrets CA-paket förnyas används
`oc rollout restart deployment/cvebridge -n image-security` för att läsa in den nya filen.

**Ny programversion:** kör `./configure.sh --new-tag`, använd de nya bygg- och
pushkommandona och applicera mappen igen. Scheman och larmstatus ligger kvar
på samma PVC. Kör en replika; lagringen behöver fungerande SQLite-fillåsning.

## Verifiering

Go-tester, skriptets utkast/återupptagning, hemliga värden, YAML-struktur,
konsekvent registry/tagg och HTTPS-flödet testas lokalt. Företagets faktiska
registry, OpenShift CA-injektion, Mattermost/ACS och PVC behöver verifieras i labbet.
`/healthz` visar bara att botprocessen svarar. Byggen här använder Docker eftersom
Podman saknas i testmiljön; samma Dockerfile används av båda.

[Slash-kommandon i Mattermost](https://docs.mattermost.com/developers/integrate/slash-commands/custom)
· [OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
· [OpenShift CA-paket](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators)
