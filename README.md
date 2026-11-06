# CVEBridge · driftbot för Mattermost

Status, imageskanning, CVE-rapporter och schemaformulär i en privat driftkanal.
Boten frågar ACS Central direkt. Driftmedlemmarna behöver inga personliga
OpenShift-konton eller användarmappningar. Scheman och larmstatus sparas på PVC.

```text
hämta → ./configure.sh → Go bygger lokalt → Podman paketerar → tagga/pusha → oc apply → testa
```

## Förbered

Ubuntu/Linux med **Go 1.27.3, Bash, Python 3, Podman och `oc`**. Git behövs bara
om du klonar; ZIP fungerar också. Projektet och en befintlig PVC ska finnas i
OpenShift. Standardprojektet är **`image-security`**; PVC:n
måste finnas i samma projekt som boten.

Installera Go från företagets godkända källa eller följ
[Gos installationsguide](https://go.dev/doc/install). Kontrollera med `go version`.
Kommandona nedan bygger för **Linux/amd64**, alltså klusternoder med Intel/AMD.
För ARM64-noder används `GOARCH=arm64` och `--platform linux/arm64` i stället.

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
logg- och skriptuppdateringen behöver du bara kopiera:

| Del | Kopiera till samma plats i ditt befintliga projekt |
| --- | --- |
| Boten | `internal/bridge/` — innehåller loggändringarna. |
| Installationsskriptet | `configure.sh` i projektets rot. |
| Guiden | `README.md` i projektets rot. |
| Tester, om du kör `go test` | `internal/setup/configure_test.go`. |

Behåll din **`deploy/`-mapp och den dolda `.local/`-mappen**. Där finns dina
ifyllda YAML-filer och sparade svar. Du behöver inte kopiera `vendor/`,
Dockerfile eller andra mappar för denna uppdatering.

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

## 3. Bygg programmet lokalt med Go

Kör efter `./configure.sh`. Go på din Ubuntu bygger den färdiga körfilen
`bin/cvebridge`. Endast registryadressen är en variabel: `$REGISTRY`.
Imagen heter `cvebridge` och taggen skrivs direkt som `latest`:

```sh
REGISTRY=$(python3 -c 'import json; print(json.load(open(".local/setup.json"))["registry"])')
mkdir -p bin/rootfs/data
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -mod=vendor -trimpath \
  -ldflags="-s -w -X main.version=latest" \
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
podman build --platform linux/amd64 -f Dockerfile -t localhost/cvebridge:latest .
podman tag localhost/cvebridge:latest "$REGISTRY/image-security/cvebridge:latest"
oc whoami -t | podman login "$REGISTRY" --username cvebridge --password-stdin
podman push "$REGISTRY/image-security/cvebridge:latest"
```

`podman tag` ger imagen registryadressen. `podman login` använder din befintliga
OpenShift-inloggning. `podman push` laddar upp imagen till `image-security`.
Vänta tills pushen är klar utan fel innan du applicerar YAML-filerna.

Imagen innehåller körfilen och den tomma datamappen. Källkod, `vendor/`, tokens
och företagsinställningar följer inte med. Saknas `bin/cvebridge`, kör steg 3 först.
Om Dockerfile fortfarande hämtar en Go-image eller kör `go mod download`,
hämta uppdateringen med `git pull --ff-only` och använd Dockerfile därifrån.

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
Go och Podman och pusha `$REGISTRY/image-security/cvebridge:latest`. **Vänta tills
pushen är klar och applicera sedan `deploy/`.** Skriptet har markerat en omstart
i Deployment så att apply skapar en ny pod, även när imageadressen är densamma.

Deployment använder `imagePullPolicy: Always`. Vid den nya podstarten kontrolleras
vilken image `latest` pekar på i registryn. En push ensam startar inte om en redan
körande pod. `--new-tag` fungerar fortfarande som alias för `--update-image`.
Scheman och larmstatus ligger kvar på samma PVC. Kör en replika; lagringen
behöver fungerande SQLite-fillåsning.

## Felsök StackRox i podloggarna

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

**Om du bara ser `Mattermost listener`:** den raden visar att mottagaren för
Mattermost-kommandon startar. Den nya versionen ska även skriva `monitor_startup`
utan att du kör något kommando. Saknas den raden, kontrollera att du har byggt om
Go-körfilen, paketerat och pushat `:latest` och därefter applicerat en uppdatering
förberedd med `./configure.sh --update-image`. Att bara kopiera källkod ger inte
den nya loggningen i en redan körande pod.

**Uppdatera via ZIP:** kopiera delarna i tabellen under steg 1 och behåll
`deploy/` och `.local/`. Kör `./configure.sh --update-image`; ifyllda uppgifter
hoppas över och befintliga installationsfiler förbereds för en ny `:latest`-image.
Följ sedan skriptets Go-, Podman-, push- och apply-kommandon.

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
· [Podman push](https://docs.podman.io/en/latest/markdown/podman-push.1.html)
· [Kubernetes image pull policy](https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy)
· [OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
· [OpenShift CA-paket](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators)
