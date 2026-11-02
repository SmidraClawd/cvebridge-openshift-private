# CVEBridge · privat OpenShift-installation

Go-boten skickar CVE-rapporter och schemaformulär direkt i Mattermost.
Databasen sparas på er befintliga PVC.

## Ditt flöde

```sh
./cvebridge.sh init
# Fyll i era 11 grundfält i .env.

docker build -t cvebridge:local .

oc login
oc project DITT_NAMESPACE
./cvebridge.sh push
```

`push` taggar den lokala imagen, loggar in mot labbets registry och pushar den.
Samtidigt genereras färdiga YAML-filer med rätt imageadress.
Taggen räknas ut från den byggda imagen. Deployment använder:

```text
image-registry.openshift-image-registry.svc:5000/<namespace>/cvebridge:<automatisk-tagg>
```

Plattformsteamet applicerar engångsbehörigheterna vid första installationen:

```sh
oc apply -f deploy/bootstrap.yaml
```

Du applicerar sedan appen:

```sh
oc apply -f deploy/app/
oc rollout status deployment/cvebridge -n DITT_NAMESPACE
```

I `deploy/app/` finns separata filer för **Deployment, Service, ConfigMap,
Secret och ServiceAccounts**. Er färdiga PVC monteras på `/data`.
Byt `DITT_NAMESPACE` mot samma projekt som i `.env`.

[Fyll i .env](docs/ENV_VARDEN.md) · [Installation och Mattermost](docs/INSTALLATION.md) · [Skärmbilder](docs/BILDER.md)

**Valfri driftbevakning:** få daglig databasstatus i Mattermost, varning vid
äldre än 24 timmar eller okänd status och besked när läget är bra igen.
Aktiveras med [ett extra fält i .env](docs/DRIFTBEVAKNING.md).

`cmd/` och `internal/` är Go-koden som Docker bygger. Du behöver inte ändra dem.
Företagsvärden finns i lokal `.env` och genererade filer, som är git-ignorerade.
