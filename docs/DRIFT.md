# Drift och uppdatering

## Ny image

```sh
docker build -t cvebridge:local .
./cvebridge.sh push
oc apply -f deploy/app/
```

Skriptet använder det byggda image-ID:t för en automatisk tagg. Deployment hämtar
imagen från labbets interna registry. Bootstrap appliceras av plattformen vid
första installationen och när de godkända namespace-behörigheterna ändras.

## Bara nya inställningar

Ändra lokal `.env`, kör `./cvebridge.sh render` och applicera `deploy/app/`.
Starta sedan om boten eftersom miljövariabler läses vid processstart:

```sh
oc rollout restart deployment/cvebridge -n DITT_NAMESPACE
oc rollout status deployment/cvebridge -n DITT_NAMESPACE
```

## Beständig databas

Boten använder `/data/requests.sqlite3` på er färdiga PVC. Den sparar scheman,
körningar, kortlivade formulär och tidigare bekräftade CVE:er. Säkerhetskopiera
lagringen enligt er rutin, helst när boten är stoppad. Behåll PVC:n vid vanliga
uppdateringar. Byte av PVC-namn flyttar inte databasen.

En replika och Recreate används. Kör inte flera botar mot samma SQLite-fil.
Pågående schemakörningar markeras som avbrutna vid omstart; missade tider spelas
inte upp som en backlogg. En krasch mellan Mattermost-bekräftelse och databasens
commit kan ge dubbelleverans. Exakt-en-gång-leverans garanteras inte.

## Felsökning

```sh
oc get pods,pvc,svc -n DITT_NAMESPACE
oc logs deployment/cvebridge -n DITT_NAMESPACE -c bot --tail=50
```

Kontrollera image-pull, PVC, nätverk, certifikat och tokens efter behov.
`/healthz` är ett processtest; verifiera anslutningarna med `/cve status` och en
riktig skanning. Tomma fynd är inget friskintyg om skannern redovisar luckor.

[Installation](INSTALLATION.md) · [PVC](NATVERKSLAGRING.md) · [Åtkomst](ACCESS.md)
