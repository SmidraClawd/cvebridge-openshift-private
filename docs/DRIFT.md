# Drift och uppgradering

Runtime och installationsgenerator är skrivna i Go. En process lyssnar på 8001:
`/healthz`, `/slash/cve`, `/slash/acs` och tidsbegränsade dialog-callbacks.
Inga inloggningssidor eller browser-identitetshuvuden används.

## Uppdatera

Efter en koduppdatering räknas image-taggen ut från Git-revisionen, eller från
projektfilerna om Git saknas. Du kan också ange `IMAGE_TAG` uttryckligen i `.env`.
Bygg, pusha och rendera igen. Applicera sedan
`deployment.yaml`. Ändringar i tokens eller ConfigMap kräver en omstart eftersom
miljövariabler läses vid processstart:

```sh
oc apply -f deploy/generated/deployment.yaml
oc rollout restart deployment/cvebridge
oc rollout status deployment/cvebridge
```

En replika och Recreate-strategin skyddar SQLite-ägarskapet. Kör inte parallella
botinstallationer mot samma databas eller samma kanal/schema. Fler repliker kräver
annan jobbsamordning och är inte en konfigurationsändring.

## Beständig state

`/data/requests.sqlite3` innehåller scheman, revisionshistorik, körningar,
kortlivade formulär och tidigare bekräftade CVE:er. Tokens finns i Kubernetes
Secret, inte i databasen. Säkerhetskopiera PVC:n enligt er rutin, helst med boten
stoppad. Radera inte PVC:n vid vanliga uppgraderingar.

Pågående schemakörningar markeras som avbrutna vid omstart. Körningar som missas
med mer än fem minuter spelas inte upp i efterhand. Manuell körning sparas inte
som ett schemalagt jobb; vid omstart kan beställaren behöva göra om den.
En krasch i den korta luckan mellan Mattermost-bekräftelse och SQLite-commit kan
ge dubbelleverans eller upprepad ping. Ingen exakt-en-gång-garanti lämnas.

## Migrera från Python-versionen

Ta en databasbackup, stoppa den gamla processen och bevara PVC:n. Go läser samma
SQLite-tabeller för scheman, körningar och CVE-bevakning. Granska och fyll i de
nya miljövariablerna i `.env.example`; gamla installationsfiler är inte direkt utbytbara.
`MATTERMOST_TOKEN`, `MATTERMOST_BOT_ID` och `SLASH_TOKEN` heter nu
`MATTERMOST_BOT_TOKEN`, valfritt `MATTERMOST_BOT_USER_ID` och `MATTERMOST_COMMAND_TOKEN`.
Bot-ID behöver normalt inte anges; den autentiserade botprofilen verifieras automatiskt.
Eventuellt `/acs` har en separat `MATTERMOST_ACS_COMMAND_TOKEN`.

Alla människor behöver en explicit `MATTERMOST_KUBE_USER_MAP` till sitt exakta
klusterkonto. OIDC-email som implicit identitet och privata webbrapporter har tagits
bort. Manuell skanning och CVE-sökning körs i godkända privata teamkanaler och
resultatet delas i kanalen enligt policyn. CVE-sökning använder nu aktiva poddars
images, precis som skanning; historiska, inaktiva deployment-images ingår inte.

Gamla browserlänkar fungerar inte. Öppna schemadialogerna igen efter uppgradering;
en redan öppen dialog kan ha en äldre identitetssnapshot. Proxy/Dex behövs inte
för Go-boten. Avveckla dem separat efter granskning om andra tjänster använder dem.
Behåll ACS-installationen, reporteridentiteten och dess godkända roller vid migration,
eller anpassa dem uttryckligen till generatorns `cvebridge-reporter`.

## Begränsningar

Ett tomt fyndresultat är inget friskintyg. Scanner-varningar, misslyckade images,
saknade underlag och gammal CVE-databas ska utredas. Inventeringen begränsas till
100 unika images och 2 000 aktiva poddar per beställning. Rapporten begränsas till
20 000 rader och 8 MiB bilaga. Avgränsa med namespace om gränserna nås.

Ny installation kräver fungerande Mattermost, ACS, klustrets RBAC, registry och
lagring. Lokala tester och lyckat imagebygge ersätter inte ett test i ert OpenShift-labb.
