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

Generatorn kopplar poddens volym till det namn du anger:

```yaml
# Utdrag ur podspecifikationen; namnet ersätts från .env.
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: CHANGE_ME_PVC
```

Containern monterar `data` på `/data`. Databasen sparas som
`/data/requests.sqlite3` och används igen när poden startar om med samma PVC.
Ingen PV, PVC eller lagrings-Secret skapas eller ändras av generatorn i detta läge.
Mattermost- och ACS-tokens tillförs fortfarande genom appens integrations-Secret.

## Bygg och starta

Följ [installationen](INSTALLATION.md): bygg, pusha, rendera och applicera manifesten.
Bootstrap behövs fortfarande för botens Kubernetes-behörighetskontroll.
Kontrollera att den befintliga lagringen är skrivbar för podens UID/grupp och
lämplig för SQLite med korrekt fillåsning och synkronisering.

Spara ett schema i Mattermost, starta om boten och kontrollera att schemat finns
kvar. Kontrollera även databasfilen på lagringen. En befintlig databas flyttas
inte automatiskt om du byter PVC. Kör en botreplika mot databasen.

## Andra installationer

Utan `STATE_EXISTING_PVC` kan generatorn skapa en ny PVC med klustrets
standard-StorageClass. Explicit ny SMB-/NFS-lagring finns som ett separat
alternativ i [env-options.example](env-options.example); det används inte för er färdiga PVC.

[Kubernetes: montera en PVC i en pod](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#claims-as-volumes).
