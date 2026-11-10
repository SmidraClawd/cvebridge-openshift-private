# Överlämning till en annan AI: CVEBridge och Mattermost-felet

Uppdaterad 2026-11-09. Kopiera texten nedan till den AI som ska hjälpa till.
Uppgifter om företagsmiljön är användarens observationer; den har inte kunnat
inspekteras direkt härifrån. Värdnamn, tokens och företagskonfiguration ingår inte.

## Senast verifierade läge

Följande resultat från 2026-11-09 ersätter den tidigare kontrollpunkten längre
ned. Klusterresultaten har rapporterats av användaren, inte verifierats genom
direkt åtkomst till företagsmiljön.

- **Mattermost-kommandon fungerar.** Både en separat testapp och CVEBridge fick
  först HTTP 302 till samma HTTPS-adress. Att ändra respektive Routes
  `insecureEdgeTerminationPolicy` från `Redirect` till `Allow` gav fungerande
  curl-anrop och Mattermost-kommandon. Det är förenligt med TLS-avslut framför
  OpenShift-routern, men den exakta nätverkstopologin har inte verifierats.
  `Allow` tillåter även HTTP till routen; Mattermost använder fortsatt HTTPS.
  Behåll miljöns fungerande val i den lokala Route-YAML-filen. Ändra inte
  projektets TLS-standard för andra miljöer utifrån detta resultat.
- **Inventeringsfrågan är rättad.** ACS kan prefixmatcha okvoterade söktermer.
  Frågan använder nu exakt matchning för både kluster-ID och namespace:
  `Cluster ID:"..."+Namespace:"..."`. Ett regressionstest återskapar felet med
  liknande namn. Kontrollen av svarets kluster och namespace finns kvar.
  `inventory_scope_mismatch` loggar förväntade och mottagna värden vid avvikelse.
- **Läsning och nya skanningar fungerar enligt användaren.** Tidigare 403 vid
  `/v1/pods` respektive `/v1/images/scan` krävde kontroll av ACS-rollens
  läsrättigheter respektive `Image: Read and Write` och dess access scope.
  `/cve report` läser befintliga resultat. `/cve scan` begär en ny skanning.
- **500 för intern registry löstes genom klustervalet.** Med
  `STACKROX_DELEGATE_SCAN: "true"` i botens ConfigMap och en podomstart skickar
  boten med befintligt `STACKROX_CLUSTER_ID` och målnamespace i skanningsanropet.
  Användaren bekräftade därefter fungerande skanning. Spara inställningen även
  i den lokala ConfigMap-YAML-filen.
- **Scan/report använder nu en kopierbar imagetabell.** Kolumnerna är namespace,
  image i drift, verifierad basimage, ACS egna riskantal och berörda tilläggspaket
  med installerad/fixversion. Workload-kolumn, JSON-bilaga och textblock är
  borttagna från dessa rapporter. Långa urval fortsätter i fler tabeller.
  Paketens ursprung kräver ACS `baseImageInfo` och giltiga historiklagerindex;
  saknad eller tvetydig basmatchning visas som okänd. Boten hittar inte på en
  uppdaterad basimage-tagg eller resultatet av en framtida ombyggnad.
- **En eller flera CVE:er kan sökas i samma körning.** `/cve CVE-ID CVE-ID`
  och `/cve search CVE-ID,CVE-ID [namespace]` läser befintliga ACS-resultat en
  gång. Högst 20 olika CVE:er; kanalens scope kontrolleras även vid varje
  publicerad tabelldel. CVE-tabellen visar namespace, image, CVE, ACS-risk,
  paketets ursprung och installerad/fixversion. Inga JSON-bilagor eller nya
  skanningar skickas. Saknad täckning skiljs från inga kända träffar, och
  sökningen förbrukar inga engångslarm. `/cve help` och README har exempel.
- **Sensor-kommandot behöver läsåtkomst till klustret.** Det använder
  `STACKROX_TOKEN` och `GET /v1/clusters/{id}`. Vid nekad åtkomst kontrolleras
  `Cluster: Read` och access scope. Ett lyckat sensorresultat har inte
  uttryckligen dokumenterats efter den senaste behörighetsfrågan.
- **Kompakta färgtabeller är ett designförslag.** Användaren har Mattermost
  11.10.1 och har fått exempelbilder med tabeller för images och paket.
  Mattermost Blocks-tabellerna och automatisk upptäckt av alla namespaces är
  ännu inte implementerade. `/cve scan` utan argument använder fortfarande
  botens konfigurerade namespace-lista och kanalens befintliga behörighetsmodell.

Boten körs i ett annat namespace än dokumentationens standardexempel
`image-security`. Använd aktuellt botnamespace i alla `oc`-kommandon. Befintliga
företagsmanifest, tokens och PVC ska bevaras. Följande avsnitt innehåller den
tidigare överlämningen och historiska observationer.

---

Du tar över felsökningen av **CVEBridge**, en Go-bot som kopplar ACS/StackRox
Central till en privat driftkanal i Mattermost. Svara på enkel svenska och ge
ett konkret test i taget. Jag vill kunna läsa av ett litet resultat och säga
exempelvis en statuskod eller ett kort värde; be mig inte klistra in hela loggar.

## 1. Källkod och vilken version som gäller

- **Aktuell OpenShift-/driftversion:**
  https://github.com/SmidraClawd/cvebridge-openshift-private
- **Tidigare publik projektversion och referensbilder:**
  https://github.com/SmidraClawd/cvebridge

Det första repot är huvudkällan för just min installation. Namnet innehåller
`private` av historiska skäl; kontrollera aktuell synlighet på GitHub. Repot har
en förenklad driftmodell som skiljer sig från den äldre publika versionens
modell med personliga Kubernetes-behörigheter. Blanda inte deras konfigurationer.

Senast kontrollerad kod före denna överlämningsfil:
`18305334bd7759d48ba3a215f0587a4362e1254e`.
Senaste runtimeändringen före den var `b1d0867`; `1830533` ändrade Route och
dokumentation. Vilken exakt imageversion som nu kör i företagsklustret är inte
verifierat. Ett befintligt lokalt bygge identifierades som `latest-5a451d0dfd2c`.

Läs främst dessa filer i det aktuella OpenShift-repot:

| Fil | Innehåll |
| --- | --- |
| `cmd/cvebridge/main.go` | Processens start, HELLO-logg, HTTP-server och lyssningsadress. |
| `internal/bridge/app.go` | HTTP-endpoints, kommandotoken, `/cve help` och kommandodispatch. |
| `internal/bridge/commands.go` | Validering av kommandon, CVE-listor och valfritt namespace. |
| `internal/bridge/config.go` | Konfigurationsvalidering och standardvärden. |
| `internal/bridge/operations.go` | Privat driftkanal, kanalmedlemmar och tillåtna namespaces. |
| `internal/bridge/services.go` | HTTP-klienter, CA-förtroende, Mattermost och ACS. |
| `internal/bridge/scan.go` | ACS-frågor, bilder, skanning och databasstatus. |
| `internal/bridge/database_monitor.go` | Automatisk kontroll av CVE-definitionernas ålder. |
| `internal/bridge/sensor_monitor.go` | Kontroll av senaste sensorkontakt enligt Central. |
| `internal/bridge/dialog.go` | Inbyggda Mattermost-formulär för scheman. |
| `internal/bridge/state.go` | SQLite, scheman, körhistorik och larmstatus. |
| `internal/bridge/report.go` | Mattermost-kort, Åtgärd och rapportformat. |
| `internal/bridge/image_report.go` | Native imagetabeller, ACS baslager, riskantal och tilläggspaket. |
| `internal/bridge/cve_report.go` | CVE-tabeller med versioner, paketursprung och tydliga rader utan träff. |
| `internal/bridge/debug.go` | Sanerade ACS-loggar. |
| `configure.sh` | Lokal Bash/Python-konfigurator och generering av manifest. |
| `route.yaml` | Manuell OpenShift Route-mall. |
| `Dockerfile`, `.dockerignore` | Källkodsbygge med vendor och slutlig scratch-image. |
| `README.md`, `deploy/README.md` | Installation och manuellt ConfigMap-/Secret-flöde. |
| `internal/**/*_test.go` | Automatiska tester. |

`deploy/` innehåller bara sin README i Git. Ifyllda företagsmanifest genereras
eller underhålls lokalt och är ignorerade. Avsaknad av ifylld Deployment eller
Secret på GitHub betyder därför inte att användaren saknar dem i företaget.

## 2. Mål och funktioner

Jag använder Ubuntu/Linux och **Podman**. Jag hämtar ofta projektet som ZIP och
kopierar ändrade filer till företagets Git/projekt. Jag har redan fyllt i
**ConfigMap, Secret och Deployment manuellt**. Bevara dessa värden och befintlig
PVC. Kör inte om konfiguratorn för att återskapa dem från gamla sparade svar.

Målet är:

1. Bygga Go-koden och imagen lokalt med Podman.
2. Tagga och pusha imagen till OpenShifts interna registry.
3. Applicera YAML i vårt namespace.
4. Använda boten, kommandon och schemaformulär direkt i Mattermost.
5. Spara scheman och larmstatus på befintlig PVC genom podomstarter.

Ingen separat webbplats ska behövas för den dagliga användningen. Det är en
vanlig Deployment med en replika, inte en Operator. Ingen certifikatsbevakning
ska byggas till. HTTPS-verifiering och tokenkontroller ska finnas kvar.

Aktuella funktioner i OpenShift-koden:

- CVE-databasstatus: kontroll vid start och sedan varje timme. Mattermost-post
  vid första kontroll, ändrat läge eller efter 24 timmar med oförändrat läge.
  Boten läser metadata via ACS API och uppdaterar inte definitionsdatabasen själv.
- Sensorstatus: när aktiverad kontrolleras senaste kontakttid i Central var
  femte minut. Äldre än tio minuter ger saknad kontakt inom tidsgränsen.
  API-fel ger okänd status, inte ett bevis på att sensorn är nere.
- Manuell imageskanning, befintliga fynd och sökning på en/flera CVE:er visas
  som svenska tabeller utan bilagor.
- Schemaformulär i Mattermost för dagar, tider, namespaces, körning/rapport,
  aktivering, paus och körhistorik. Formulärens multiselect kräver Mattermost 11+.
- SQLite på `/data/requests.sqlite3` via PVC. Den rensas inte dagligen.
- Begränsning av upprepade kritiska CVE-pingar genom sparad status.

Kommandon:

```text
/cve help
/cve status
/cve sensor
/cve scan team-a
/cve report team-a
/cve CVE-2021-44228 team-a
/cve CVE-2025-47273 CVE-2022-40897
/cve search CVE-2025-47273,CVE-2022-40897 team-a
/cve schedule
```

`SCAN_NAMESPACES` är en lista över tillåtna namespaces. `/cve scan` utan
namespace väljer hela den konfigurerade listan. `*` stöds inte.

I driftläget behövs ingen `MATTERMOST_KUBE_USER_MAP` eller personlig
OpenShift-inloggning för varje kanalmedlem. Boten kontrollerar den godkända
privata driftkanalen och medlemskap. Den frågar **ACS Central**, inte sensorns
eget API eller ACS-databasen direkt. Central använder data från klustrets Sensor.

## 3. Konfiguration och byggflöde

Standardnamespace i exemplen: `image-security`. Bekräfta det verkliga namnet
innan kommandon körs i ett annat projekt. Standardimage:

```text
image-registry.openshift-image-registry.svc:5000/image-security/cvebridge:latest
```

Endast registryadressen ska vara en terminalvariabel, `$REGISTRY`. Ingen
`LOCALIMAGE`- eller separat imagevariabel önskas. Det dokumenterade flödet är:

```sh
export REGISTRY="image-registry.openshift-image-registry.svc:5000"
podman build --network=none --platform linux/amd64 -f Dockerfile -t localhost/cvebridge:latest .
podman tag localhost/cvebridge:latest "$REGISTRY/image-security/cvebridge:latest"
oc whoami -t | podman login "$REGISTRY" --username cvebridge --password-stdin
podman push "$REGISTRY/image-security/cvebridge:latest"
oc apply -f deploy/
oc rollout restart deployment/cvebridge -n image-security
oc rollout status deployment/cvebridge -n image-security
```

Det här är ett exempel på uppdateringsflödet, inte ett krav att bygga om för
felsökningen. Ändringar i Route/NetworkPolicy kräver normalt inte nytt imagebygge.
Manuellt ändrade miljövärden från ConfigMap/Secret behöver en podomstart.

Bygget använder Go 1.27.3, lokala beroenden i `vendor/`, `GOPROXY=off`,
`-mod=vendor` och statisk Go-kompilering. Första hämtningen av byggimagen kan
fortfarande behöva nätverk. Slutlig image är `scratch` med bara körfil och `/data`.
CA-paketet levereras från klustret via en monterad ConfigMap på
`/ca/ca-bundle.crt`. Använd inte borttagen TLS-verifiering som lösning.

Viktiga ConfigMap-nycklar, utan företagsvärden:

```text
ACCESS_MODE=operations
LISTEN_ADDR=:8001
STATE_FILE=/data/requests.sqlite3
MATTERMOST_INTERNAL_URL=https://<mattermost-server>
MATTERMOST_CHANNEL_ID=<privata-driftkanalens-id>
MATTERMOST_DIALOG_URL=https://<botens-route>/slash/cve/dialog
SCAN_NAMESPACES=team-a,team-b
STACKROX_URL=https://<acs-central>
STACKROX_CLUSTER_ID=<acs-kluster-id>
DATABASE_MONITOR_CHANNEL_ID=<privata-driftkanalens-id>
STACKROX_SCANNER_COMPONENT=SCANNER_V4
DATABASE_MAX_AGE_HOURS=24
SENSOR_MONITOR_ENABLED=true
MATTERMOST_CA_FILE=/ca/ca-bundle.crt
STACKROX_CA_FILE=/ca/ca-bundle.crt
```

Tokens ligger i Secret: `MATTERMOST_BOT_TOKEN`, `MATTERMOST_COMMAND_TOKEN` och
`STACKROX_TOKEN`. Koden kan också använda separat `STACKROX_STATUS_TOKEN`.
Begär inte tokenvärden i chatten. Secret-data i base64 är inte anonymiserade.

`configure.sh` är ett lokalt hjälpverktyg som lagrar svar i `.local/setup.json`
och genererar YAML. Det bygger, pushar eller installerar inte åt användaren.
Skriptet importerar inte manuellt ändrade YAML-filer och kan skriva över dem
med sparade värden. Användaren arbetar nu med de befintliga manifesten direkt.

## 4. Det tidigare Mattermost-problemet

**Automatiska statusmeddelanden från boten når Mattermost-kanalen. Men när jag
kör `/cve help`, eller andra `/cve`-kommandon, får jag `Internal error`.**

Det automatiska utgående flödet fungerar åtminstone för databasstatus:

```text
CVEBridge -> ACS Central API
CVEBridge -> Mattermost API -> driftkanal
```

Det inkommande kommandoflödet behöver felsökas:

```text
Mattermost-server -> HTTPS till botens Route
                 -> OpenShift-router med edge TLS
                 -> botens HTTP-endpoint på port 8001
                 -> POST /slash/cve
```

Viktiga kodfakta:

- `main.go` använder vanlig `ListenAndServe()` och standardadressen `:8001`,
  alltså inte en server som bara binds till localhost. `LISTEN_ADDR` kan ändras
  via konfiguration; företagsvärdet är inte direkt kontrollerat härifrån.
- `GET /healthz` ger 200. Route-mallen exponerar `/slash/cve` och dess
  undersökvägar, så `/healthz` är inte ett giltigt hälsotest genom just den routen.
- Kommandot tar emot **POST `/slash/cve`**. GET till den sökvägen ger 404.
- Utan giltig kommandotoken ger POST exakt:

```text
HTTP 401
{"error":"Kommandot kunde inte verifieras."}
```

- Med giltig token ger `/cve help` ett direkt 200 JSON-svar med hjälpen. Det
  anropar inte ACS. Ett ACS-tokenfel förklarar därför inte ensamt att help faller.
- Om både Authorization-header och formulärets token finns kräver koden att
  båda matchar. Efter att anslutningen fungerar kan detta behöva jämföras med
  aktuell Mattermost-konfiguration, särskilt om OAuth ändrar headern.
- Den kontrollerade kommandohanteraren returnerar inte HTTP 302 eller 503 för
  help. Andra interna funktioner kan ha felstatus; läs rätt HTTP-kodväg.
- Det finns HELLO/versionslogg och ACS-loggar, men ingen generell accesslogg för
  varje inkommande HTTP-anrop. En tyst podlogg bevisar därför inte att inget anrop
  har nått handlern. Vilken image som faktiskt kör behöver också verifieras.

## 5. Observationer före Route-rättningen

1. **Direkt test via Service-port-forward fungerade.**

   Första terminalen:

   ```sh
   oc port-forward -n image-security service/cvebridge-webhook 18001:8001
   ```

   Andra terminalen:

   ```sh
   curl -i -X POST http://127.0.0.1:18001/slash/cve
   ```

   Jag fick det förväntade 401-svaret med botens svenska JSON-feltext.
   Det visar att boten kan svara via port-forward. Det bevisar inte att
   routern eller Mattermost-servern har nätverksåtkomst till poden.

2. **Test via HTTPS-Route misslyckades.** Tidigare rapporterades `302 Found`.
   Exakt Location-header och vilken begäran som gav 302 är inte dokumenterat.
   Användaren upplevde att länken var korrekt. Anta inte en verifierad redirect-loop.

3. Därefter rapporterades:

   ```text
   OpenSSL SSL_read
   error:0A000126
   unexpected eof while reading
   ```

   Hela raden och curl-numret inom parentes har inte delats. Felkoden betyder
   ett oväntat avslut på TLS-anslutningen; den bevisar inte ett CA-fel.

4. I curl-utskriften, även efter ett test med `--http1.1`, såg jag ungefär:

   ```text
   connection established / using HTTP/1.x
   Request completely sent off
   HTTP/1.0 503 Service Unavailable
   ```

   **503 är nu huvudledtråden.** Vem som genererar det svaret är ännu inte
   fastställt. Det kan vara OpenShift-router eller annan proxy/load balancer.
   Anta inte att 503 kommer från boten eller att det är ett bevisat kodfel.

5. Route `cvebridge-webhook` har kontrollerats och TLS termination är **`edge`**.
   Det är rätt modell för denna HTTP-backend; passthrough är inte avsikten.

6. `oc get endpoints cvebridge-webhook -n image-security` visade en IP-adress.
   Exakt adress, port, portnamn och eventuell beredskapsinformation är inte
   insamlade. Vi ska inte påstå att alla dessa är verifierade.

7. Route-kontrollen visade portnamnet **`webhook`**. I projektets generator heter
   både Service-porten och containerporten `webhook`, med numerisk port 8001.
   Alla aktuella kopplingar i företagsklustret är inte fullständigt dokumenterade.

8. Användaren hittade nätverksregler med namn ungefär:

   ```text
   allow-from-hostnetwork
   allow-from-kube-api
   allow-from-ingress
   deny-all-ingress
   ```

   Exakta objektnamn har inte kopierats. I ingress-tillåtelseregeln såg jag:

   ```text
   PodSelector: <none>
   To Port: <any>
   NamespaceSelector: network.openshift.io/policy-group: ingress
   ```

   `<none>` i describe betyder här alla pods i namespace. `<any>` innebär att
   regeln inte begränsar destinationsport. Men källans namespace måste fortfarande
   matcha selectorn. Standard-NetworkPolicy-regler är additiva: en vanlig
   deny-all-regel upphäver inte en annan matchande allow-regel. Ändra inte regler
   baserat enbart på deras namn.

## 6. Den tidigare kontrollpunkten före Route-rättningen

Senaste föreslagna testet var att se om `openshift-ingress` faktiskt har den
label som tillåtelseregeln väljer:

```sh
oc get namespace openshift-ingress \
  -o jsonpath='{.metadata.labels.network\.openshift\.io/policy-group}{"\n"}'
```

För att just den selectorn ska matcha detta namespace ska svaret vara `ingress`.
**Användaren har ännu inte lämnat resultatet.** Be gärna om bara `ingress`,
`tomt` eller `felmeddelande`, inte hela manifestet.

Om svaret är tomt är just den namespace-matchningen inte verifierad. Det räcker
inte för att slå fast grundorsaken: den faktiska routern kan använda hostNetwork,
andra regler kan tillåta trafiken, eller 503 kan komma från en annan komponent.
Kontrollera faktisk IngressController, router-namespace och publiceringsstrategi
om det behövs. Lägg inte blint labels på klusterägda namespace.

## 7. Metod vid eventuell fortsatt felsökning

Läs koden och jämför sedan med minimala observationer från klustret. Föreslå
ett litet, läsbart kommando i taget med exakt vad jag ska leta efter.

Prioritera att skilja mellan:

1. Felaktig eller ej antagen Route, fel hostname/path/backend/portnamn.
2. Endpoint som inte motsvarar rätt lyssnande och tillgänglig pod.
3. Trafik från routern som inte tillåts av relevanta nätverkspolicyer.
4. 503 eller avbruten anslutning från företagets proxy/load balancer.
5. Mattermost-serverns egen DNS, nätverksåtkomst, CA-förtroende eller regler för
   interna integrationsmål, efter att Route har testats från rätt ursprung.
6. Kommando-token, formulär/header, metod, exakt sökväg eller kodfel efter att
   nätverksvägen har verifierats. Förklara vad testresultatet faktiskt bevisar.

Jag vill uppnå:

- POST till HTTPS-routen utan token ger botens 401-JSON, utan omdirigering.
- `/cve help` från Mattermost ger hjälpsvar.
- Därefter fungerar status, sensor, skanning och schemaformulär.

Behåll HTTPS-verifiering, tokens, PVC och företagets befintliga inställningar.
Begär inte tokenvärden, full Secret, kubeconfig eller privata TLS-nycklar.
Föreslå inte att öppna all ingress som standardlösning. Om en ändring behövs,
visa den minsta relevanta ändringen och hur den verifieras. Gör inte ett nytt
imagebygge till första åtgärd utan belägg för att koden eller imagen är problemet.

Jag kan inte ge dig direkt tillgång till företagsmiljön. Påstå inte att du har
ändrat, sett eller verifierat den om jag inte har lämnat resultat från den.

## Referenser och tidigare verifiering

Kodversion `1830533` har 60 Go-testfunktioner och en lyckad GitHub Actions-körning:
https://github.com/SmidraClawd/cvebridge-openshift-private/actions/runs/42518059176

Det är test av projektet, inte ett godkänt integrationstest av företagets Route,
Mattermost, nätverk eller OpenShift-installation.

Primärkällor att använda vid behov:

- https://docs.mattermost.com/developers/integrate/slash-commands/custom
- https://github.com/mattermost/mattermost/blob/master/server/channels/app/command.go
- https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/network_security/network-policy
- https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/ingress_and_load_balancing/routes
- https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/
- https://kubernetes.io/docs/concepts/services-networking/network-policies/
- https://mta.openssl.org/pipermail/openssl-users/2022-January/014814.html

Utgå från det senaste verifierade läget överst. Vid ett nytt fel, sammanfatta
vad som är verifierat och vad som är osäkert och ge sedan en konkret kontroll.
Git-åtkomst till repot fungerade även när webbläsningen misslyckades. Kontrollera
befintlig Git-åtkomst innan du ber användaren om en annan anslutning eller ZIP.
