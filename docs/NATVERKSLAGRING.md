# Använd er färdiga PVC

Lagringsanslutningen finns redan i OpenShift. Boten behöver bara PVC:ns namn
för att montera den som `/data`.

## Välj projekt och PVC

Namespace väljs med `oc project`. PVC-namnet fylls direkt i Deployment-filens
`claimName`, utan någon miljöfil.

Byt mot projektet där PVC:n finns och dess riktiga namn. Du hittar dem med:

```sh
oc get pvc -n ert-projekt
```

PVC:n måste finnas i samma namespace som boten. Du anger ingen nätverkssökväg,
lagringsanvändare eller lagringslösenord i appens konfiguration.
Plattformen hanterar serveranslutningen och lagringens behörigheter.

## Vad som hamnar i Deployment

Ändra `claimName` manuellt i `deploy/app/deployment.yaml` till PVC-namnet:

```yaml
# Utdrag ur podspecifikationen; fyll i den befintliga PVC:ns namn.
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: CHANGE_ME_PVC
```

Containern monterar `data` på `/data`. Databasen sparas som
`/data/requests.sqlite3` och används igen när poden startar om med samma PVC.
De färdiga YAML-filerna skapar ingen PV, PVC eller lagrings-Secret.
Mattermost- och ACS-tokens tillförs fortfarande genom Secret `cvebridge-tokens`.

## Bygg och starta

Följ [installationen](INSTALLATION.md): bygg, tagga, pusha och applicera de färdiga YAML-filerna.
Driftläget behöver inget bootstrap-steg eller någon Kubernetes-behörighetskontroll.
Kontrollera att den befintliga lagringen är skrivbar för podens UID/grupp och
lämplig för SQLite med korrekt fillåsning och synkronisering.

Spara ett schema i Mattermost, starta om boten och kontrollera att schemat finns
kvar. Kontrollera även databasfilen på lagringen. En befintlig databas flyttas
inte automatiskt om du byter PVC. Kör en botreplika mot databasen.

Plattformsteamet hanterar PV/PVC och eventuell nätverksmontering separat.

[Kubernetes: montera en PVC i en pod](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#claims-as-volumes).
