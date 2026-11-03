# Drift och uppdatering

## Ny image

Följ de manuella Docker-kommandona i README. Använd en ny tagg och uppdatera
`image` i `deploy/app/deployment.yaml`. Applicera sedan:

```sh
oc apply -f deploy/app/deployment.yaml
oc rollout status deployment/cvebridge
```

Bootstrap uppdateras av plattformsteamet om godkända namespaces ändras.

## Bara nya inställningar

Ändra lokal `.env`, importera den och starta om boten:

```sh
oc project DITT_NAMESPACE
oc create secret generic cvebridge-integration --from-env-file=.env --dry-run=client -o yaml | oc apply --server-side --field-manager=cvebridge-env -f -
oc rollout restart deployment/cvebridge
oc rollout status deployment/cvebridge
```

Ändrad standardkonfiguration i `deploy/app/configmap.yaml` appliceras med
`oc apply -f deploy/app/configmap.yaml` före omstarten.

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
