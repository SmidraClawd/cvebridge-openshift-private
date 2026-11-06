# CVEBridge · driftbot för Mattermost

Status, imageskanning, CVE-rapporter och schemaformulär i en privat driftkanal.
Boten frågar ACS Central direkt. Driftmedlemmarna behöver inga personliga
OpenShift-konton eller användarmappningar. Scheman och larmstatus sparas på PVC.

```text
hämta → ./configure.sh → Podman bygger kod och image → tagga/pusha → oc apply → HELLO i loggen
```

## Förbered

Ubuntu/Linux med **Bash, Python 3, Podman och `oc`**. Git behövs bara
om du klonar; ZIP fungerar också. Projektet och en befintlig PVC ska finnas i
OpenShift. Standardprojektet är **`image-security`**; PVC:n
måste finnas i samma projekt som boten.

Go finns i byggimagen; du behöver inte installera Go på datorn för att bygga boten.
Kommandona nedan bygger för **Linux/amd64**, alltså klusternoder med Intel/AMD.
För ARM64-noder används `--platform linux/arm64` i stället.

Kommandona använder terminalvariabeln **`REGISTRY`**, med `$REGISTRY` när värdet
ska användas. Standardvärdet är klustrets interna registry:

```text
image-registry.openshift-image-registry.svc:5000/image-security/cvebridge:latest
```

Variabelnamnet skrivs med stora bokstäver; värdet är serveradressen, utan
`https://` eller imagesökväg. Ubuntu-maskinen och klustret behöver kunna nå
den valda registryn och lita på dess CA. Samma registry används för taggning,
push och Deployment. För standardadressen behöver Ubuntu nå klustrets interna DNS.

## 1. Hämta projektet och logga in

Vid första hämtningen:

```sh
git clone https://github.com/SmidraClawd/cvebridge-openshift-private.git
cd cvebridge-openshift-private
```

Har du redan projektet via Git kan du uppdatera med:

```sh
git pull --ff-only
```

**Använder du ZIP?** Packa upp den nya ZIP-filen separat. För den senaste
bygg- och logguppdateringen behöver du kopiera:

| Del | Kopiera till samma plats i ditt befintliga projekt |
| --- | --- |
| Boten | `internal/bridge/` — innehåller loggändringarna. |
| Uppstartsmeddelandet | `cmd/cvebridge/main.go` — skriver `HELLO` direkt vid start. |
| Bygget | `Dockerfile` och den dolda filen `.dockerignore` — kopiera båda. |
| Installationsskriptet | `configure.sh` i projektets rot. |
| Guiden | `README.md` i projektets rot. |
| Tester, om du kör `go test` | `internal/setup/configure_test.go`. |

Behåll din **`deploy/`-mapp och den dolda `.local/`-mappen**. Där finns dina
ifyllda YAML-filer och sparade svar. Behåll också `vendor/`, `go.mod` och
`go.sum` från projektet. Saknas `vendor/`, hämta hela privata ZIP-paketet och
behåll dina lokala inställningar när du kopierar in koden.

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

Första gången frågar skriptet efter namespace, PVC, projektlista, ACS,
Mattermost och tokens. Nästa gång läser det `.local/setup.json` och **frågar
bara efter tomma fält**. Är allt redan ifyllt ställs inga frågor.
Det uppdaterar filerna i din befintliga `deploy/`-mapp och använder taggen `latest`
i kommandona och Deployment. Formuläradressen räknas ut från botens Route.

Vill du välja en annan registry, ange den före skriptet. Värdet sparas och
behöver inte anges igen:

```sh
export REGISTRY="image-registry.openshift-image-registry.svc:5000"
./configure.sh
```

Byt bara serveradressen ovan om ni använder en annan registry. Den ska vara
nåbar även från klustret eftersom Deployment använder samma adress.

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

`DATABASE_MONITOR_CHANNEL_ID` i den genererade ConfigMap är Mattermost-kanalen
för CVE-databasens status. Skriptet använder samma ID som driftkanalen, så du
behöver inget extra värde. Tomt eller saknat fält stänger av automatisk bevakning.

**Tomma svar:** Enter lämnar ett saknat värde till senare. Redan ifyllda fält
hoppas över. För att ändra ett sparat svar, kör `./configure.sh --edit`.
I det läget behåller Enter värdet och `-` rensar det. Tokens visas aldrig.

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
Det finns ingen `.env`-fil i installationsflödet. Sparade skriptsvar är källan
när YAML-filerna återskapas. Behåll därför `.local/` när du uppdaterar via ZIP.
Har du bara manuellt ifyllda YAML-filer och inga sparade svar behöver uppgifterna
föras in i skriptet en gång; behåll en lokal kopia av dina YAML-filer tills dess.

## 3. Bygg boten med Podman

Kör efter `./configure.sh`. Endast registryadressen är en variabel: `$REGISTRY`.
Dockerfile bygger Go-programmet från aktuell källkod och paketerar det i imagen.
Du behöver inget separat `go build` och ingen fil från `bin/` används.

```sh
REGISTRY=$(python3 -c 'import json; print(json.load(open(".local/setup.json"))["registry"])')
podman build --network=none --platform linux/amd64 -f Dockerfile -t localhost/cvebridge:latest .
```

Go-paketen följer med i `vendor/`. Kompileringen använder `-mod=vendor`,
`GOPROXY=off` och nätverket är avstängt med `--network=none`. Det hindrar
Go från att ladda ner paket under bygget, inklusive `go-humanize`.

Första gången kan Podman behöva hämta `docker.io/library/golang:1.27.3`.
För helt frånkopplat bygge måste den byggimagen redan finnas lokalt, hämtad
från företagets godkända källa. `--network=none` gäller byggstegen, inte hämtningen
av byggimagen. Certifikatkontrollen är kvar för registry, Mattermost och ACS.
Vänta tills bygget är klart utan fel innan du fortsätter.

## 4. Tagga och pusha

Imagen från steg 3 heter `localhost/cvebridge:latest`. Tagga och pusha den:

```sh
podman tag localhost/cvebridge:latest "$REGISTRY/image-security/cvebridge:latest"
oc whoami -t | podman login "$REGISTRY" --username cvebridge --password-stdin
podman push "$REGISTRY/image-security/cvebridge:latest"
```

`podman tag` ger imagen registryadressen. `podman login` använder din befintliga
OpenShift-inloggning. `podman push` laddar upp imagen till `image-security`.
Vänta tills pushen är klar utan fel innan du applicerar YAML-filerna.

Den slutliga imagen innehåller bara körfilen och den tomma datamappen `/data`.
Go-byggimagen, källkod, `vendor/`, tokens och företagsinställningar följer inte
med till den slutliga imagen. PVC:n monteras på `/data` i OpenShift.

Skriptet skriver också ut färdiga kommandon med `$REGISTRY` som enda variabel.
Image, tagg och namespace skrivs direkt i kommandona med rätt värden. Du kan
kopiera dem som alternativ till steg 3–4. Det kör inget av kommandona åt dig.

## 5. Starta boten i OpenShift

Kontrollera att konfigurationen är komplett:

```sh
./configure.sh --check
```

När kontrollen är godkänd och imagen är pushad, applicera hela mappen och
kontrollera att boten startar. Här används standardprojektet `image-security`;
byt det i kontrollkommandona om boten körs i ett annat namespace. Skriptets
utskrivna kommandon har redan ditt sparade namespace:

```sh
oc apply -f deploy/
oc rollout status deployment/cvebridge -n image-security
oc logs deployment/cvebridge -n image-security -c bot --tail=50
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
oc get configmap cvebridge-trusted-ca -n image-security
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

**Fyll i det som saknas:** kör `./configure.sh`. Sparade värden behålls,
bara tomma fält efterfrågas och den befintliga `deploy/`-mappen uppdateras.

**Ändra en befintlig inställning eller token:** kör `./configure.sh --edit`.
Behåll taggen och kör sedan:

```sh
oc apply -f deploy/
```

Skriptet markerar ändringen i Deployment så poden startas om automatiskt vid apply.
Ingen ny image behövs. När enbart klustrets CA-paket förnyas används
`oc rollout restart deployment/cvebridge -n image-security` för att läsa in den nya filen.

**Ny programversion med `latest`:** kör först:

```sh
./configure.sh --update-image
```

Skriptet behåller sparade uppgifter och frågar bara om något saknas. Bygg om med
Podman och pusha `$REGISTRY/image-security/cvebridge:latest`. **Vänta tills
pushen är klar och applicera sedan `deploy/`.** Skriptet har markerat en omstart
i Deployment så att apply skapar en ny pod, även när imageadressen är densamma.

Deployment använder `imagePullPolicy: Always`. Vid den nya podstarten kontrolleras
vilken image `latest` pekar på i registryn. En push ensam startar inte om en redan
körande pod. `--new-tag` fungerar fortfarande som alias för `--update-image`.
Scheman och larmstatus ligger kvar på samma PVC. Kör en replika; lagringen
behöver fungerande SQLite-fillåsning.

## Felsök StackRox i podloggarna

Direkt vid processens start ska du se:

```text
HELLO CVEBridge | version=latest-<källkods-id> | startup=source-build-v1
```

ID:t beräknas från koden i bygget. Det visar vilken byggd version som körs,
även när imagetaggen alltid är `latest`. `HELLO` visar att programmet har startat;
ACS-anslutningens resultat kommer i bevakningens loggar nedan.

Med `DATABASE_MONITOR_CHANNEL_ID` ifyllt kontrollerar boten CVE-databasens ålder
via ACS API **direkt vid uppstart och sedan varje timme**. Den ansluter inte till
ACS:s databas. En ny Mattermost-post skickas vid första kontrollen, ändrat läge
eller när 24 timmar gått sedan föregående post. Sparad status på PVC:n gör att
en omstart med samma status normalt inte ger en extra post.

Uppstarten och varje automatisk kontroll ger `[ACS INFO]` i podloggen,
även med `LOG_LEVEL=info`:

| Händelse i loggen | Betydelse |
| --- | --- |
| `monitor_startup` | Visar om bevakningen är aktiverad, om ACS-token finns och om debug är på. `enabled:false` förklarar vilket fält som saknas. |
| `monitor_acs_start` | Kontrollen av CVE-databasens ålder börjar. |
| `monitor_acs_complete` | ACS-resultat: `recent`, `stale` eller `unknown`, med orsak vid fel, exempelvis HTTP 403. |
| `monitor_post_sent` | Mattermost har bekräftat statusmeddelandet. |
| `monitor_post_skipped` | Oförändrad status har redan skickats inom 24 timmar. ACS har ändå kontrollerats. |
| `monitor_check_failed` | Visar om kontrollen stoppade vid lokal lagring, kontroll av driftkanalen eller publicering i Mattermost. |
| `monitor_retry_scheduled` | Ett nytt försök görs efter cirka fem minuter. |

Den privata boten skriver felsökningsloggar med prefixet `[ACS DEBUG]`.
Du ser API-adress utan queryvärden, GET/POST, HTTP-kod, svarstyp, tidsåtgång
och namnet på tokeninställningen. Skanningen loggar även antal poddar/images
och varför ett skanningsresultat inte kunde användas. Tokens, headers för
autentisering och innehållet i anrop eller svar skrivs inte ut.

Visa loggar efter uppstart, eller följ dem medan du startar en skanning i Mattermost:

```sh
oc logs -f deployment/cvebridge -n image-security -c bot --tail=100
```

```text
/cve scan team-a
```

Byt namespace och `team-a` om du valt andra projekt. Vid HTTP 403 visar
loggen vilket anrop som nekades och vilken behörighet du ska kontrollera.
Certifikat-, DNS- och timeoutfel får separata `error_kind`-värden.
Du kan stänga av debug med `oc set env deployment/cvebridge LOG_LEVEL=info -n image-security`.
Sätt `LOG_LEVEL=debug` på samma sätt för att aktivera igen.

**Om du bara ser `Mattermost listener`:** den nya versionen ska även skriva
`HELLO CVEBridge` och `monitor_startup` utan något kommando från Mattermost.
Kontrollera att du kopierat den nya koden, Dockerfile och `.dockerignore`, byggt
och pushat `:latest` och därefter applicerat uppdateringen som förbereddes med
`./configure.sh --update-image`.

Jämför bygg-ID lokalt och i poden:

```sh
podman run --rm localhost/cvebridge:latest version
oc exec deployment/cvebridge -n image-security -c bot -- /cvebridge version
```

Efter en lyckad uppdatering ska båda visa samma `latest-...`-ID.

**Uppdatera via ZIP:** kopiera delarna i tabellen under steg 1 och behåll
`deploy/` och `.local/`. Kör `./configure.sh --update-image`; ifyllda uppgifter
hoppas över och befintliga installationsfiler förbereds för en ny `:latest`-image.
Följ sedan skriptets Podman-, push- och apply-kommandon.

## Verifiering

Go-tester, skriptets utkast/återupptagning, hemliga värden, YAML-struktur,
konsekvent registry/tagg och HTTPS-flödet testas lokalt. Företagets faktiska
registry, OpenShift CA-injektion, Mattermost/ACS och PVC behöver verifieras i labbet.
`/healthz` visar bara att botprocessen svarar. Byggen här använder Docker eftersom
Podman saknas i testmiljön; samma Dockerfile används av båda. Bygget testas
från källkod med nätverket avstängt och utan en lokal `bin/cvebridge` som källa.
Vi kontrollerar bygg-ID, `HELLO`, datamapp, lagringsskrivning och att källkod
och företagsinställningar inte hamnar i den slutliga imagen.

[Go-paket från vendor](https://go.dev/ref/mod#vendoring)
· [Dockerfile med byggsteg](https://docs.docker.com/build/building/multi-stage/)
·
[Slash-kommandon i Mattermost](https://docs.mattermost.com/developers/integrate/slash-commands/custom)
· [Podman push](https://docs.podman.io/en/latest/markdown/podman-push.1.html)
· [Kubernetes image pull policy](https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy)
· [OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
· [OpenShift CA-paket](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators)
