# Använd er färdiga PVC

Lagringsanslutningen finns redan i OpenShift. Boten behöver bara PVC:ns namn
för att montera den som `/data`.

## Två värden i .env

```dotenv
NAMESPACE=CHANGE_ME_NAMESPACE
STATE_EXISTING_PVC=CHANGE_ME_PVC
```

Byt mot projektet där PVC:n finns och dess riktiga namn. Du hittar dem med:

```sh
oc get pvc -n ert-projekt
```

PVC:n måste finnas i samma namespace som boten. Du anger ingen nätverkssökväg,
lagringsanvändare eller lagringslösenord. Utelämna `STATE_NETWORK_URL`,
`STORAGE_CLASS`, `STATE_STORAGE_SIZE` och alla `STATE_SMB_*` för detta flöde.
Plattformen hanterar serveranslutningen och lagringens behörigheter.

## Vad som hamnar i Deployment

Ändra `claimName` manuellt i `deploy/app/deployment.yaml` till PVC-namnet:

```yaml
# Utdrag ur podspecifikationen; fyll i samma namn som STATE_EXISTING_PVC.
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: CHANGE_ME_PVC
```

Containern monterar `data` på `/data`. Databasen sparas som
`/data/requests.sqlite3` och används igen när poden startar om med samma PVC.
De färdiga YAML-filerna skapar ingen PV, PVC eller lagrings-Secret.
Mattermost- och ACS-tokens tillförs fortfarande genom appens integrations-Secret.

## Bygg och starta

Följ [installationen](INSTALLATION.md): bygg, tagga, pusha och applicera de färdiga YAML-filerna.
Bootstrap behövs fortfarande för botens Kubernetes-behörighetskontroll.
Kontrollera att den befintliga lagringen är skrivbar för podens UID/grupp och
lämplig för SQLite med korrekt fillåsning och synkronisering.

Spara ett schema i Mattermost, starta om boten och kontrollera att schemat finns
kvar. Kontrollera även databasfilen på lagringen. En befintlig databas flyttas
inte automatiskt om du byter PVC. Kör en botreplika mot databasen.

Plattformsteamet hanterar PV/PVC och eventuell nätverksmontering separat.

[Kubernetes: montera en PVC i en pod](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#claims-as-volumes).
