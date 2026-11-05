# CVEBridge · driftbot för Mattermost

Status, imageskanning, CVE-rapporter och schemaformulär i en privat driftkanal.
Boten frågar ACS Central direkt. Driftmedlemmarna behöver inga personliga
OpenShift-konton eller användarmappningar. Scheman och larmstatus sparas på PVC.

```text
hämta → ./configure.sh → Go bygger lokalt → Podman paketerar → tagga/pusha → oc apply → testa
```

## Förbered

Ubuntu/Linux med **Go 1.27.3, Git, Bash, Python 3, Podman och `oc`**. Projektet och en befintlig
PVC ska finnas i OpenShift. Standardprojektet är **`image-security`**; PVC:n
måste finnas i samma projekt som boten.

Installera Go från företagets godkända källa eller följ
[Gos installationsguide](https://go.dev/doc/install). Kontrollera med `go version`.
Kommandona nedan bygger för **Linux/amd64**, alltså klusternoder med Intel/AMD.
För ARM64-noder används `GOARCH=arm64` och `--platform linux/arm64` i stället.

Registryadressen är fast i detta flöde:

```text
image-registry.openshift-image-registry.svc:5000/image-security/cvebridge:<automatisk-tagg>
```

Ubuntu-maskinen måste kunna nå denna interna DNS/adress och lita på registryts
CA. Det här flödet använder samma interna adress för taggning, push och Deployment.
En vanlig dator utanför klustrets nät kan behöva nätverks-/DNS-åtkomst ordnad av
plattformsteamet för att nå just den adressen.

## 1. Hämta projektet och logga in

Vid första hämtningen:

```sh
git clone https://github.com/SmidraClawd/cvebridge-openshift-private.git
cd cvebridge-openshift-private
```

Har du redan projektet, öppna terminalen i projektmappen och hämta uppdateringen:

```sh
git pull --ff-only
```

I OpenShift-konsolen: klicka på ditt användarnamn → **Copy login command**.
Kör inloggningskommandot i terminalen. Kontrollera sedan kontot och PVC-namnet:

```sh
oc whoami
oc get pvc -n image-security
```

PVC:n ska vara **Bound**. Byt `image-security` om boten ska köras i ett annat
projekt. Kör resten av stegen i **samma terminal, från projektmappen**.

## 2. Fyll i genom skriptet

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

### Testa ACS från Ubuntu

Har du fått HTTP 403 i Mattermost? Testa med dina sparade ACS-uppgifter:

```sh
./configure.sh --test-acs
```

Testet läser adress och token från dina sparade svar. Det ändrar inga filer och
visar inte tokenen. Du behöver varken bygga programmet eller starta boten.

- **200:** svaret kontrolleras som ACS-data. Driftstatus ska ge en uppdateringstid.
- **401:** kontrollera tokenens giltighet.
- **403:** kontrollera tokenens roll, särskilt **Administration → Read** för driftstatus. En proxy kan också neka anropet.
- **Certifikatfel:** kontrollera företagets CA på Ubuntu.

`https://central.foretaget.se` och `https://central.foretaget.se:443` använder
samma HTTPS-port. Port 443 är normal. Ange Central-adressen utan `/main` eller
`/v1`; testet lägger till rätt API-sökväg. Testet gäller åtkomsten från Ubuntu;
podens nätverk, proxy och CA-paket kan skilja sig.

## 3. Bygg programmet lokalt med Go

Kör efter `./configure.sh`. Go på din Ubuntu bygger den färdiga körfilen
`bin/cvebridge`. Första raden läser samma tagg som används i Deployment:

```sh
CVEBRIDGE_TAG=$(python3 -c 'import json; print(json.load(open(".local/setup.json"))["tag"])')
mkdir -p bin/rootfs/data
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -mod=vendor -trimpath \
  -ldflags="-s -w -X main.version=$CVEBRIDGE_TAG" \
  -o bin/cvebridge ./cmd/cvebridge
chmod 0755 bin/cvebridge
chmod 0770 bin/rootfs/data
```

Go-paketen följer med projektet i `vendor/`. Go läser dem lokalt utan att hämta
paket eller en annan Go-version från internet. Ingen certifikatkontroll stängs av.
`bin/rootfs/data` blir den tomma lagringsplatsen `/data` i imagen. PVC:n monteras
på `/data` i OpenShift.

Om Go saknas eller är för gammalt, installera Go 1.27.3 innan du fortsätter.
Vänta tills Go-bygget är klart utan fel. Kör om detta steg efter kodändringar.

## 4. Paketera med Podman, tagga och pusha

Dockerfile paketerar den färdiga körfilen. Den bygger ingen Go-kod och hämtar
ingen byggimage. Kör med taggen från steg 3:

```sh
podman build --platform linux/amd64 -f Dockerfile -t "localhost/cvebridge:$CVEBRIDGE_TAG" .
CVEBRIDGE_IMAGE="image-registry.openshift-image-registry.svc:5000/image-security/cvebridge:$CVEBRIDGE_TAG"
podman tag "localhost/cvebridge:$CVEBRIDGE_TAG" "$CVEBRIDGE_IMAGE"
oc whoami -t | podman login image-registry.openshift-image-registry.svc:5000 --username cvebridge --password-stdin
podman push "$CVEBRIDGE_IMAGE"
```

`podman tag` ger imagen registryadressen. `podman login` använder din befintliga
OpenShift-inloggning. `podman push` laddar upp imagen till `image-security`.
Vänta tills pushen är klar utan fel innan du applicerar YAML-filerna.

Imagen innehåller körfilen och den tomma datamappen. Källkod, `vendor/`, tokens
och företagsinställningar följer inte med. Saknas `bin/cvebridge`, kör steg 3 först.
Om Dockerfile fortfarande hämtar en Go-image eller kör `go mod download`,
hämta uppdateringen med `git pull --ff-only` och använd Dockerfile därifrån.

Skriptet skriver också ut färdiga kommandon med taggen redan ifylld. Du kan
kopiera dem som alternativ till steg 3–4. Det kör inget av kommandona åt dig.

## 5. Starta boten i OpenShift

Kontrollera att konfigurationen är komplett:

```sh
./configure.sh --check
```

När kontrollen är godkänd och imagen är pushad, applicera hela mappen och
kontrollera att boten startar. Namespace läses från dina sparade svar:

```sh
CVEBRIDGE_NAMESPACE=$(python3 -c 'import json; print(json.load(open(".local/setup.json"))["namespace"])')
oc apply -f deploy/
oc rollout status deployment/cvebridge -n "$CVEBRIDGE_NAMESPACE"
oc logs deployment/cvebridge -n "$CVEBRIDGE_NAMESPACE" -c bot --tail=50
```

Alla YAML-filer har redan rätt namespace. `deploy/` innehåller ConfigMap, Secret, Deployment,
ServiceAccount, Service, CA-ConfigMap och Route när ett Route-värdnamn är angivet.
Deployment heter `z-deployment.yaml` så ConfigMap och Secret appliceras före omstarten.
Väljer du annat botnamespace än `image-security` skapas även `image-puller.yaml`;
kontot som kör apply behöver då rätt att ge image-pull-åtkomst i `image-security`.

OpenShift fyller den separata `cvebridge-trusted-ca` med klustrets betrodda
CA-paket. Det monteras på `/ca/ca-bundle.crt`; imagen innehåller inga CA-filer.
CA:n som utfärdat Mattermosts och ACS certifikat måste ingå i klusterpaketet.
Kontrollera att CA-paketet har fyllts i; kommandot ska visa `DATA: 1`:

```sh
oc get configmap cvebridge-trusted-ca -n "$CVEBRIDGE_NAMESPACE"
```

Botens ServiceAccount behöver ingen Kubernetes-API-token eller personlig RBAC.

## 6. Testa i Mattermost

Bjud in boten till den privata driftkanalen. Registrera `/cve` under
**Integrations → Slash Commands** med metoden **POST** och Request URL
`https://BOTENS_ROUTE/slash/cve`. Skriptet visar den fullständiga adressen.
Om du lämnade kommandotoken tom, kopiera tokenen från Mattermost och kör
`./configure.sh` igen, följt av `oc apply -f deploy/`. Ingen ny image behövs.

Skriv sedan i driftkanalen:

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
Podman saknas i testmiljön; samma Dockerfile används av båda. Go-bygget testas
med tom modulcache och paketnedladdning avstängd. Paketeringen testas med
nätverket avstängt, följt av kontroll av körfil, datamapp och containerns start.

[Go-paket från vendor](https://go.dev/ref/mod#vendoring)
·
[Slash-kommandon i Mattermost](https://docs.mattermost.com/developers/integrate/slash-commands/custom)
· [OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
· [OpenShift CA-paket](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators)
