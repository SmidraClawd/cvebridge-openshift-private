# Installation och nätverk

Den fullständiga manuella ordningen finns i [README](../README.md): fyll `.env`,
bygg/tagga/pusha med Docker, redigera färdiga YAML och applicera med `oc`.
Du behöver Docker eller Podman, `oc`, ett befintligt projekt med PVC och
åtkomst till ACS Central, Mattermost och labbets registry.

## Färdiga filer

`deploy/app/` använder det namespace du väljer med `oc project`.
Deployment innehåller två värden du ändrar själv: **image** och **claimName**.
`deploy/bootstrap.yaml` innehåller plattformsbehörigheterna och redigeras en gång
med botens namespace och varje godkänt app-namespace.

`.env` importeras till Secret med det vanliga `oc create secret`-kommandot i
README. Den byggs inte in i imagen och behöver inte kopieras till någon server.
Kubernetes läser Secret via Deployment-filens `envFrom`.

## Mattermost ställs in en gång

Skapa boten med rollen **Member**, bjud in den till den privata rapportkanalen
och registrera **Integrations → Slash Commands → Add Slash Command**:

| Fält | Värde |
| --- | --- |
| Command Trigger Word | `cve` |
| Request Method | `POST` |
| Request URL | `http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve` |

Byt `DITT_NAMESPACE`. Kopiera botens Access Token och kommandots Token till `.env`.
Servern behöver nå både kommandot och formulärens callback. Om interna anslutningar
blockeras godkänner Mattermost-admin just tjänstens värdnamn i
`AllowedUntrustedInternalConnections`.

## Om Mattermost behöver en extern route

1. Byt `CHANGE_ME_HOST` i `deploy/optional/route.yaml` till ert godkända värdnamn.
2. Byt Deployment-filens `MATTERMOST_DIALOG_URL` till
   `https://ERT_VARDNAMN/slash/cve/dialog`.
3. Applicera `oc apply -f deploy/optional/route.yaml` i botens projekt.
4. Ange `https://ERT_VARDNAMN/slash/cve` som Mattermost-kommandots Request URL.
5. Applicera den ändrade Deployment-filen.

Intern Service är standard. En route behöver inte skapas när den interna
anslutningen redan fungerar. Edge-routen använder klustrets vanliga routecertifikat.

## Om Central eller Mattermost använder intern CA

Be respektive systemansvarig om den publika CA-kedjan i PEM-format. Spara den
lokalt, exempelvis i `certs/central-ca.pem`. Skapa en ConfigMap manuellt:

```sh
oc create configmap cvebridge-ca --from-file=central.pem=certs/central-ca.pem --dry-run=client -o yaml | oc apply -f -
```

Lägg till detta i Deployment under `spec.template.spec.volumes`:

```yaml
- name: ca
  configMap:
    name: cvebridge-ca
```

Lägg till under containerns `volumeMounts`:

```yaml
- name: ca
  mountPath: /ca
  readOnly: true
```

Lägg sedan till `STACKROX_CA_FILE=/ca/central.pem` i `.env`, importera Secret
igen och applicera Deployment. För Mattermost används motsvarande fil och
`MATTERMOST_CA_FILE=/ca/mattermost.pem`; inkludera då även
`--from-file=mattermost.pem=certs/mattermost-ca.pem` när ConfigMap skapas.
Lägg båda `--from-file`-argumenten i samma kommando när båda CA-filerna behövs.

## Kontrollera installationen

```sh
oc get pods,pvc,svc
oc rollout status deployment/cvebridge
oc logs deployment/cvebridge -c bot --tail=50
```

Testa `/cve status`, `/cve scan team-a` och `/cve schedule` i rapportkanalen.
Namespace-behörigheterna kontrolleras för användarna; reporterrollen behövs
också för scheman. Företagets riktiga anslutningar verifieras i ert labb.
`/healthz` kontrollerar endast botprocessen.

Källor: [Mattermost slash-kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom),
[OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry),
[Kubernetes ConfigMap-volym](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/).
