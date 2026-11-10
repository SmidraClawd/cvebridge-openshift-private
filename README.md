# CVEBridge · driftbot för Mattermost

Databasstatus, sensorkontakt, imageskanning och schemaformulär i en privat driftkanal.
Boten frågar ACS Central direkt. Driftmedlemmarna behöver inga personliga
OpenShift-konton eller användarmappningar. Scheman och larmstatus sparas på PVC.

`/cve scan` och `/cve report` visar en kopierbar tabell med **namespace, image
i drift, basimage, fynd och berörda appaket**. Inga Workload-kolumner,
JSON-bilagor eller textblock läggs till skanningsrapporten.

**Har du redan databasstatus i driftkanalen?** Följ stegen under
[uppdatera befintlig installation](#uppdatera-befintlig-installation).
Aktivera sedan kommandon och scheman med [steg 6](#6-aktivera-cve-och-scheman-i-mattermost).

**Redigerar du ConfigMap och Secret manuellt?** Steg 6 visar även det flödet,
utan skript. En färdig [Route-fil](route.yaml) finns i projektets rot.

**Felsöker du inkommande Mattermost-kommandon?**
[AI-överlämningen](AI_HANDOFF.md) samlar kodöversikt, rapporterade 503-/TLS-fel,
genomförda kontroller och nästa kontroll. Företagsvärden och tokens ingår inte.

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
| Boten | `internal/bridge/` inklusive `testdata/` — innehåller imagetabellen och loggarna. |
| Uppstartsmeddelandet | `cmd/cvebridge/main.go` — skriver `HELLO` direkt vid start. |
| Bygget | `Dockerfile` och den dolda filen `.dockerignore` — kopiera båda. |
| Installationsskriptet | `configure.sh` i projektets rot. |
| Guiden | `README.md` i projektets rot. |
| Manuell Route | `route.yaml` i projektets rot. Kopiera därifrån till `deploy/route.yaml` när Route saknas. |
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

Skriptet lägger även in `SENSOR_MONITOR_ENABLED: "true"`. Sensorbevakningen
använder **samma kanal, ACS-adress, ACS-token och kluster-ID**. Inga nya frågor
eller tokens behövs. Kluster-ID ska peka på labbklustret som ni vill bevaka.
Tokenen behöver **Cluster: Read** och access scope för det klustret.

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

## 6. Aktivera /cve och scheman i Mattermost

Detta görs en gång. Vanlig användning och schemaformuläret är sedan helt inne
i Mattermost. Automatisk status behöver inte `/cve` för att fungera.

### A. Kontrollera botens adress

Visa botens Route i OpenShift:

```sh
oc get route cvebridge-webhook -n image-security
```

Kopiera värdet under **HOST/PORT**. Exempel: `cvebridge.apps.labb.foretaget.se`.
Kommandots adress blir då `https://cvebridge.apps.labb.foretaget.se/slash/cve`.
Det är **botens adress**, inte Mattermosts adress. Skriptet skriver också ut
den kompletta adressen.

**Finns bara Service `cvebridge-webhook`, men ingen Route?** Kopiera den färdiga
filen från projektets rot till din befintliga `deploy/`-mapp och applicera den:

```sh
cp route.yaml deploy/route.yaml
oc apply -f deploy/route.yaml
oc get route cvebridge-webhook -n image-security
```

Filen använder namespace `image-security` och projektets standardport `8001`.
Byt namespace i filen om boten körs någon annanstans. OpenShift väljer värdnamnet
automatiskt eftersom filen inte anger `spec.host`. En ny Route kräver inget
nytt imagebygge eller någon omstart av boten.

Testa routen utan att skicka en token eller skapa något Mattermost-meddelande:

```sh
curl -i -X POST "https://$(oc get route cvebridge-webhook -n image-security -o jsonpath='{.spec.host}')/slash/cve"
```

Förväntat svar är **HTTP 401** och JSON-texten
`{"error":"Kommandot kunde inte verifieras."}`. Just detta svar bekräftar
att anropet nådde botens kommandokontroll. Testet saknar avsiktligt token.
Routen leder bara `/slash/cve` och dess undersökvägar; testa inte `/healthz`
genom denna Route.

Mattermost-servern måste kunna nå den adressen via HTTPS och lita på dess CA.
Boten behöver samtidigt kunna nå Mattermost och ACS Central. En fungerande
automatisk statusrapport bekräftar inte att anrop i motsatt riktning fungerar.
Visar Mattermost-loggen `address forbidden` behöver Mattermost-ansvarig
godkänna botens specifika värdnamn bland tillåtna interna integrationsmål.

**HTTP 302 tillbaka till samma HTTPS-adress?** Kontrollera var HTTPS avslutas
framför OpenShift-routern. Om en framförliggande lastbalanserare använder HTTP
till routern kan Route-inställningen `Redirect` orsaka en ny omdirigering.
I en sådan installation kan den befintliga routen behöva
`insecureEdgeTerminationPolicy: Allow`, medan Mattermost fortsatt använder
HTTPS-adressen. `Allow` tillåter även HTTP till routen. Anpassa valet till
installationens TLS-upplägg och spara det i er lokala Route-YAML; projektets
standardmall använder fortsatt `Redirect`.

### B. Registrera kommandot

Gå till samma Mattermost-team som driftkanalen och öppna
**Integrations → Slash Commands → Add Slash Command**. Fyll i alla fält:

| Fält | Ange |
| --- | --- |
| Title | `CVEBridge` |
| Description | `Databasstatus, sensorkontakt och imageskanning för driften.` |
| Command Trigger Word | `cve`, utan `/` |
| Request URL | `https://DITT-ROUTE-VARDNAMN/slash/cve`, med värdnamnet från A |
| Request Method | `POST` |
| Response Username | Lämna tomt. |
| Response Icon | Lämna tomt. |
| Autocomplete | Kryssa i. |
| Autocomplete Hint | `help, status, sensor, scan [namespace], report [namespace], search CVE-ID [namespace], schedule` |
| Autocomplete Description | `Kontrollera ACS, skanna images, sök CVE:er och skapa scheman.` |

De två sista fälten visas efter att Autocomplete har kryssats i. Lämna en eventuell
valfri OAuth-koppling utan koppling. Klicka **Save** och kopiera **Token** på
bekräftelsesidan. Det är ett enda kommando, `cve`, som hanterar samtliga funktioner.

Saknas menyn eller rätten att skapa kommandot behöver Mattermost-ansvarig
registrera det eller tillåta det för dig. Driftmedlemmar behöver inte vara
administratörer för att använda ett registrerat kommando.

### C. Spara token och formuläradress manuellt

Öppna dina befintliga YAML-filer. Behåll övriga värden och tokens.

1. I `deploy/secret.yaml`: lägg till eller uppdatera `MATTERMOST_COMMAND_TOKEN`
   under `stringData` med tokenen från B. Ändra inte botens eller ACS token.
2. I `deploy/configmap.yaml`: ange `MATTERMOST_DIALOG_URL` under `data`.
   Värdet är `https://DITT-ROUTE-VARDNAMN/slash/cve/dialog`, med samma värdnamn som A.
3. Kör från projektmappen:

```sh
oc apply -f deploy/
oc rollout restart deployment/cvebridge -n image-security
oc rollout status deployment/cvebridge -n image-security
```

Omstarten läser in de ändrade värdena. Ingen `.env`, skriptkörning eller nytt
imagebygge behövs för dessa inställningsändringar. Dela inte tokenen i kanalen
eller chatten. Routen behöver vara nåbar även från Mattermost-servern.

**Om du använder skriptet i stället:** kör `./configure.sh` för saknade värden
eller `./configure.sh --edit` för ändrade värden, sedan `oc apply -f deploy/`.
Skriptet genererar filerna från `.local/setup.json`, inte från manuella YAML-ändringar.
Det skapar bara en Route när ett Route-värdnamn finns sparat; det kan ta bort en
manuellt skapad `deploy/route.yaml` lokalt om det sparade Route-värdnamnet är tomt.

### D. Testa manuellt i den privata driftkanalen

Bjud in boten och kör kommandona ett i taget:

| Skriv | Förväntat resultat |
| --- | --- |
| `/cve help` | Hjälp med tillgängliga kommandon. |
| `/cve status` | CVE-databasens uppdateringstid och ålder. |
| `/cve sensor` | Senaste sensorkontakt för det konfigurerade klustret. |
| `/cve scan` | Ny imageskanning av driftkanalens godkända namespaces, sedan imagetabellen. |
| `/cve scan team-a` | Samma tabell för ett godkänt namespace. |
| `/cve report` | Imagetabell från befintliga ACS-resultat för kanalens namespaces. |
| `/cve report team-a` | Befintligt underlag för ett godkänt namespace, utan ny skanning. |
| `/cve CVE-2025-47273` | Tabell med de namespaces, images och paket där denna CVE hittats. |
| `/cve CVE-2025-47273 CVE-2022-40897` | Sök flera CVE:er i en enda körning. |
| `/cve search CVE-2025-47273,CVE-2022-40897 team-a` | Samma sökning med kommatecken och ett valt namespace. |

**CVE-sökning:** ange högst 20 olika CVE-ID:n med mellanslag eller kommatecken.
Stora/små bokstäver spelar ingen roll och dubbletter tas bort. Utan ett namespace
sist används alla projekt som driftkanalen får se. Sökningen läser befintliga
ACS-skanningar; den begär ingen ny skanning och ändrar inte larmens historik.

Resultatet är en kopierbar tabell med **namespace, image, CVE, ACS-risk,
paket/ursprung, installerad version och fixversion**. Ursprung visas som basimage,
appens tillägg eller ej verifierat. Fixversionen gäller den sökta CVE:n och är
inte ett löfte att paketet saknar andra sårbarheter. Varje CVE utan kända träffar
får också en rad. Saknat eller delvis underlag visas uttryckligen och räknas
inte som ett bevis på att CVE:n saknas. Långa resultat fortsätter i fler tabeller,
utan JSON-bilaga eller dropdown. `/cve help` visar kommandona i Mattermost.

Tabellen använder vanlig Mattermost-text. Färgade rubriker används när servern
har [inbyggd inline-LaTeX](https://docs.mattermost.com/end-user-guide/collaborate/format-messages#math-formulas)
aktiverad, annars används vanliga rubriker automatiskt. Ingen plugin behövs.
Du kan markera och kopiera en rad. Samma format används för manuella och
schemalagda `scan`/`report`; större urval fortsätter i fler tabeller.

| Kolumn | Innehåll |
| --- | --- |
| Namespace | OpenShift-projektet där imagen körs. |
| Image i drift | Deployerad image och tagg. Underlaget hämtas med poddens digest. |
| Basimage (ACS) | Basens namn och version när ACS kan verifiera lagermatchningen; annars **Ej verifierad**. |
| Fynd i imagen | ACS egna kritiska, höga, övriga och ej bedömda fynd för hela imagen. Delvis eller saknat underlag markeras i cellen. |
| Appens tillägg (fynd) | Alla identifierade tilläggspaket med fynd: paket, installerad version → fixversion enligt ACS. |

En paketfixversion är **inte en ny image-tagg**. Boten gissar ingen ny basversion
eller framtida minskning av fynd. Jämförelsen med en ombyggd kandidat i labbet
var ett separat test. Utan ACS basimage-matchning kan paketens ursprung inte
fastställas, och då visas **Ursprung ej verifierat**. ACS kan behöva konfigureras
för basimage-detektering av plattformsteamet. Saknas en gemensam paketfix anger
tabellen detta; versioner från olika CVE:er jämförs inte som vanlig text.

Fynd räknas per paketversion/CVE inom imagen. Om samma image körs i flera
namespaces visas den på varje berörd rad; summera inte dessa rader som unika
fynd. Långa paketlistor fortsätter på fler rader utan ett godtyckligt toppurval.
Nya kritiska CVE:er kan fortfarande ge en engångsping; övriga rapporter består
bara av tabellen. Även CVE-sökningar skickas som tabeller utan JSON-bilaga.

Byt `team-a` mot ett projekt i din `SCAN_NAMESPACES`. Vänta på resultatet innan
du startar nästa skanning. Alla driftkanalens medlemmar kan använda de godkända
projekten. Första kompletta CVE-rapporten skapar normalt ett utgångsläge utan
akut ping; senare nya kritiska fynd kan ge en engångsping.

### E. Skapa ett schema i Mattermost

1. Skriv `/cve schedule` i driftkanalen. Ett formulär öppnas i Mattermost.
2. Välj exempelvis **måndag–fredag**, **08:00**, **Europe/Stockholm** och ert projekt.
3. Välj **Ny skanning och rapport** eller **Rapport från befintliga fynd**.
4. Välj **Aktiverat**, **Spara inställningar** och tryck **Utför**.
5. Öppna `/cve schedule` igen och välj **Provkör sparat schema** för att testa nu.
6. Kontrollera rapporten i kanalen. I samma formulär kan du pausa och visa körhistorik.

Formulärets flervalsfält kräver Mattermost **11.0 eller senare**. Schemat och
historiken ligger på PVC:n. Databas- och sensorbevakningen körs oberoende av
skanningsschemat; du behöver inte skapa ett schema för statusmeddelanden.

| Om något inte fungerar | Kontrollera |
| --- | --- |
| `/cve` hittas inte | Trigger `cve`, rätt Mattermost-team och att kommandot har sparats. Autocomplete styr bara förslagslistan. |
| Kommandot kan inte nå boten | Mattermost-serverns nätverk/DNS till botens Route och att Request URL slutar med `/slash/cve`. |
| Kommandot kunde inte verifieras | Token från just detta slash-kommando ska vara sparad som kommandotoken hos boten. |
| Formuläret öppnas inte eller kan inte sparas | `MATTERMOST_DIALOG_URL` ska vara botens Route + `/slash/cve/dialog`; Mattermost behöver nå även den sökvägen. |
| ACS svarar HTTP 403 | Kontrollera rättigheten för just anropet i podloggen: Administration: Read för databasstatus, Cluster: Read för sensor, Image: Write för ny skanning. |

**API-skanning av images i ett klusterinternt registry:** när skanningen ska
utföras med hjälp av det valda säkrade klustret, lägg till följande i er
befintliga ConfigMap under `data`:

```yaml
STACKROX_DELEGATE_SCAN: "true"
```

Boten skickar då med `STACKROX_CLUSTER_ID` och bildens målnamespace i
skanningsanropet till ACS. Kontrollera att kluster-ID avser rätt kluster och
att dess skanner är tillgänglig. Applicera er befintliga ConfigMap och starta
om botens Deployment för att läsa det nya miljövärdet. Spara värdet i er lokala
YAML; det skapas inte automatiskt av konfiguratorn. Ett HTTP 500 i sig anger
inte grundorsaken; kvarstår felet behöver ACS-skanningsfelet kontrolleras.

## Uppdatera befintlig installation

Du behöver inte börja om eller fylla i företagets värden igen om `.local/` finns kvar.

1. Packa upp den nya ZIP-filen separat. Kopiera **`internal/bridge/`, `configure.sh`,
   `route.yaml` och `README.md`** till motsvarande plats i ditt projekt. Kopiera även
   `internal/setup/` om du kör tester. Om du inte redan har källkodsbygget med
   HELLO, kopiera också `Dockerfile`, `.dockerignore` och `cmd/cvebridge/main.go`.
2. Behåll **`.local/`, `deploy/`, `vendor/`, `go.mod`, `go.sum` och din PVC**.
3. Kör följande från projektmappen efter din vanliga `oc login`. Kommandona
   nedan använder standardnamespace `image-security`; byt det om boten körs i
   ett annat projekt. Använder ni annan registry, ändra endast värdet i `REGISTRY`.

```sh
export REGISTRY="image-registry.openshift-image-registry.svc:5000"
./configure.sh --update-image
./configure.sh --check
podman build --network=none --platform linux/amd64 -f Dockerfile -t localhost/cvebridge:latest .
podman tag localhost/cvebridge:latest "$REGISTRY/image-security/cvebridge:latest"
oc whoami -t | podman login "$REGISTRY" --username cvebridge --password-stdin
podman push "$REGISTRY/image-security/cvebridge:latest"
oc apply -f deploy/
oc rollout status deployment/cvebridge -n image-security
oc logs deployment/cvebridge -n image-security -c bot --tail=100
```

Kör nästa kommando först när föregående lyckats. Vänta särskilt på lyckad push
innan `oc apply`. Uppdateringen aktiverar sensorbevakningen automatiskt genom
ConfigMap, utan nya frågor. Databasstatus och sparade scheman ligger kvar.
Den nya tabellen för sensorstatus skapas automatiskt i befintlig SQLite-databas.

För **enbart imagetabellens uppdatering** behöver ZIP-användare kopiera
`internal/bridge/` och `README.md`. Behåll era ifyllda YAML-filer, `.local/` och
PVC. Bygg och pusha med kommandona ovan. Använder ni `latest` och er befintliga
Deployment redan pekar rätt, starta därefter om den så den hämtar nya imagen:

```sh
oc rollout restart deployment/cvebridge -n image-security
oc rollout status deployment/cvebridge -n image-security
```

Kör sedan `/cve scan` eller `/cve report` i driftkanalen. Inga nya ConfigMap-
eller Secret-fält behövs för rapportformatet.

Saknas sparade skriptsvar men du har manuellt ifyllda YAML-filer, läs först
avsnittet om `.local/setup.json` under steg 2. Skriptet importerar inte YAML-värden.

## Automatisk sensorbevakning

Boten läser **det kluster som `STACKROX_CLUSTER_ID` pekar på** via ACS Central:

```text
Labbsensor → ACS Central ← CVEBridge → privat driftkanal
```

Kontroll görs vid start och sedan **var femte minut**. Är senaste registrerade
sensorkontakten äldre än **tio minuter** skickas ett rött meddelande med kluster,
senaste kontakttid och **Åtgärd: kontrollera Sensor-poden och nätverket till Central**.
Med normal kontrolltakt upptäcks en sådan åldersgräns inom cirka 10–15 minuter
från senaste kontakten. Det är Centrals uppgift om senaste kontakt som bedöms,
inte ett direkt nätverkstest mot sensorn eller en kontroll av alla ACS-komponenter.

När en färsk kontakttid åter syns kommer **Kontakt återställd**. Om ACS inte kan
läsas, exempelvis HTTP 403 eller timeout, visas **Sensorkontakten kan inte verifieras**.
Det betyder inte i sig att sensorn är nere. Kontrollera då anslutning, kluster-ID,
tokenens **Cluster: Read** och access scope.

Första kontrollen, ändrat läge och därefter högst en rapport per 24 timmar vid
oförändrat läge skickas till samma driftkanal som databasstatus. Status lagras
på PVC så en vanlig podomstart inte skickar samma larm igen. Meddelandena
innehåller ingen `@channel`-ping. Ett misslyckat Mattermost-anrop försöks igen.
Certifikats utgångsdatum bevakas inte.

Manuell kontroll: `/cve sensor`. Automatiken kan stängas av genom att sätta
`SENSOR_MONITOR_ENABLED: "false"` i ConfigMap och starta om boten. Skriptets
genererade standard är `true`; en senare skriptkörning återskapar den standarden.

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
| `sensor_monitor_startup` | Visar aktivering, kluster-ID och kontroll var femte minut. |
| `sensor_monitor_acs_complete` | Sensorkontakt: `connected`, `missing` eller `unknown`, med orsak och senaste kontakt. |
| `sensor_monitor_post_sent` / `sensor_monitor_post_skipped` | Ny sensorstatus levererad eller oförändrad status redan skickad. |
| `sensor_monitor_check_failed` | Visar om lokal lagring, kanalverifiering eller Mattermost-publicering misslyckades. |

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
· [Formulär i Mattermost](https://docs.mattermost.com/developers/integrate/plugins/interactive-dialogs)
· [Mattermost och interna integrationsadresser](https://docs.mattermost.com/developers/integrate/slash-commands)
· [ACS kluster-API](https://github.com/stackrox/stackrox/blob/master/proto/api/v1/cluster_service.proto)
· [ACS senaste sensorkontakt](https://github.com/stackrox/stackrox/blob/master/proto/storage/cluster.proto)
· [Podman push](https://docs.podman.io/en/latest/markdown/podman-push.1.html)
· [Kubernetes image pull policy](https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy)
· [OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
· [OpenShift CA-paket](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators)
