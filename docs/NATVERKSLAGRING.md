# Spara databasen på er nätverkslagring

Ange serverns delade mapp i din lokala `.env`:

```dotenv
STATE_NETWORK_URL=//filserver.intern/bot-state
```

`//server/delning` och `\\server\delning` behandlas som **SMB/Windows-delning**.
Ingen `https://` ska läggas till. Bekräfta protokollet med lagringsansvarig.
För NFS används i stället `nfs://server/export/bot-state` eller `server:/export/bot-state`.
Lämna fältet tomt om ni vill använda klustrets vanliga StorageClass.

## SMB: fyll i lagringskontot

Kopiera bara dessa rader från `.env.advanced.example` om kontot inte redan finns
i en Kubernetes Secret:

```dotenv
STATE_SMB_USERNAME=CHANGE_ME
STATE_SMB_PASSWORD=CHANGE_ME
# STATE_SMB_DOMAIN=CHANGE_ME
```

Byt platshållarna. Kontot kommer från lagringsansvarig och är separat från
Mattermost- och ACS-kontona. Domän anges bara om den behövs. Lösenordet ska inte
finnas i sökvägen, imagen, Git eller chatten. `.env` är git-ignorerad.

Har plattformsteamet redan skapat en Secret? Utelämna inloggningsraderna och ange
`STATE_SMB_SECRET=namnet-pa-er-secret`. Standardnamnet är `cvebridge-storage`.
Den ska finnas i botens namespace och ha nycklarna `username`, `password` och
vid behov `domain`. Generatorn skriver då inte över den befintliga Secret:en.

## Vad generatorn skapar

1. `bootstrap.yaml`: en PV som pekar på den angivna nätverksmappen, reserverad för
   botens namespace och PVC. Plattformsteamet applicerar den.
2. `deployment.yaml`: PVC:n `cvebridge-state`, eventuell SMB-Secret och poddens
   montering på `/data`.
3. Boten sparar SQLite-filen som `/data/requests.sqlite3`. Filen ligger därmed på
   er lagringsserver och används igen när podden ersätts.

Kör som vanligt `./cvebridge.sh build`, `./cvebridge.sh push` och
`./cvebridge.sh render`. Applicera bootstrap före deployment enligt
[startguiden](../START_HAR.md). Filerna är privata; deployment innehåller tokens
och eventuellt lagringslösenord.

## Plattformsteamet kontrollerar en gång

- OpenShift-noderna når servern och har rätt monteringsstöd. För SMB behövs
  CSI-drivrutinen `smb.csi.k8s.io`; kontrollera med `oc get csidriver smb.csi.k8s.io`.
  För NFS behöver servern tillåta nodernas åtkomst till exporten.
- Mappen finns, är avsedd för just denna bot och tillåter podens UID/grupp att
  skapa, skriva, synkronisera, låsa och ta bort filer. SMB använder grupp `0`,
  katalogläge `0770` och filläge `0660`; vid annat godkänt grupp-ID kan
  `STATE_SMB_GID` ändras. Inga extra podprivilegier läggs till.
- Filservern och drivrutinen stöder SQLite med tillförlitlig fillåsning och
  synkronisering. Vi använder rollback-journal, full synkronisering, en replika
  och `Recreate`. Det ersätter inte ett riktigt test på er lagring.

Använd inte `STORAGE_CLASS` samtidigt med `STATE_NETWORK_URL`. Nätverks-PVC:n
binds uttryckligen till sin PV och använder inte CephFS-klassen av misstag.
`STATE_STORAGE_SIZE` är som standard `1Gi`; för en befintlig delning sätter detta
PV/PVC-kapaciteten, ingen kvot på själva filservern. PV:n har policyn `Retain`.

## Om boten redan har en PVC

Ett ändrat `.env` flyttar inte databasen och kan inte byta lagring för en redan
bunden PVC. Stoppa boten, ta en verifierad backup och låt plattformsteamet flytta
databasen och ordna rätt bindning innan den startas igen. Radera inte den gamla
PVC:n för att lösa ett bindningsfel.

Efter en nyinstallation: kontrollera `oc get pvc cvebridge-state`, spara ett schema
i Mattermost, starta om boten och kontrollera att schemat finns kvar. Kontrollera
också att databasfilen syns i rätt mapp på servern.

Källor: [Kubernetes PV/PVC](https://kubernetes.io/docs/concepts/storage/persistent-volumes/),
[SMB-drivrutinens parametrar](https://github.com/kubernetes-csi/csi-driver-smb/blob/master/docs/driver-parameters.md),
[SQLite på nätverkslagring](https://www.sqlite.org/useovernet.html).
