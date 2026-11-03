# Installation och nätverk

Den fullständiga manuella ordningen finns i [README](../README.md): fyll ConfigMap och Secret,
bygg/tagga/pusha med Podman, redigera färdiga YAML och applicera med `oc`.
Du behöver Podman, `oc`, ett befintligt projekt med PVC och
åtkomst till ACS Central, Mattermost och labbets registry.

## Färdiga filer

`deploy/app/` använder det namespace du väljer med `oc project`.
Deployment innehåller två värden du ändrar själv: **image** och **claimName**.
`deploy/bootstrap.yaml` innehåller plattformsbehörigheterna och redigeras en gång
med botens namespace och varje godkänt app-namespace.

Fyll `deploy/app/configmap.yaml` med konfiguration och kopiera
`deploy/app/secret.yaml.example` till lokal `secret.yaml` för tokenvärdena.
Kubernetes läser båda via Deployment-filens `envFrom`. Ingen `.env` behövs
och inga företagsvärden byggs in i imagen.

## Mattermost ställs in en gång

Skapa boten med rollen **Member**, bjud in den till den privata rapportkanalen
och registrera **Integrations → Slash Commands → Add Slash Command**:

| Fält | Värde |
| --- | --- |
| Command Trigger Word | `cve` |
| Request Method | `POST` |
| Request URL via botens route | `https://ERT_BOT_VARDNAMN/slash/cve` |

Byt `ERT_BOT_VARDNAMN` mot botens route enligt nästa avsnitt. Kopiera botens
Access Token och kommandots Token till `stringData` i din lokala Secret-fil. Mattermost-servern behöver nå
både kommandot och formulärens callback. Botens utgående anslutning till
Mattermosts API använder separat `MATTERMOST_INTERNAL_URL`; den får vara er
vanliga HTTPS-adress trots variabelnamnet.

## Om Mattermost behöver en extern route

1. Byt `CHANGE_ME_HOST` i `deploy/optional/route.yaml` till ert godkända värdnamn.
2. Byt ConfigMaps `MATTERMOST_DIALOG_URL` till
   `https://ERT_VARDNAMN/slash/cve/dialog`.
3. Applicera `oc apply -f deploy/optional/route.yaml` i botens projekt.
4. Ange `https://ERT_VARDNAMN/slash/cve` som Mattermost-kommandots Request URL.
5. Applicera ConfigMap och starta om Deployment enligt README.

Manifesten innehåller alltid en intern Service. När Mattermost-servern ligger
utanför klustret och inte når tjänsten direkt används route-stegen ovan.
Routens adress behöver vara nåbar från Mattermost-servern; den behöver inte vara
öppen på internet. Edge-routen använder klustrets vanliga routecertifikat.

Om Mattermost redan når Service direkt kan Request URL vara
`http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve`, och formulärens
callback i ConfigMap anges som
`http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve/dialog`. Om sådana interna anslutningar blockeras kan
Mattermost-admin godkänna tjänstens värdnamn i `AllowedUntrustedInternalConnections`.

## Klustrets betrodda CA-paket

Detta är redan inkopplat i de färdiga OpenShift-filerna:

```text
Klustrets betrodda CA-paket → cvebridge-trusted-ca → /ca/ca-bundle.crt → boten
```

`deploy/app/trusted-ca.yaml` skapar en separat, tom ConfigMap med etiketten
`config.openshift.io/inject-trusted-cabundle: "true"`. OpenShifts Cluster Network
Operator fyller den med systemets och klustrets konfigurerade extra CA-certifikat.
Deployment monterar paketet skrivskyddat. Båda CA-sökvägarna i appens ConfigMap
pekar redan på `/ca/ca-bundle.crt`. `oc apply -f deploy/app/` applicerar allt.

**Företagets CA för Mattermost och ACS måste finnas i paketet.** Kluster-API:ts
CA och certifikaten för era HTTPS-adresser kan ha olika utfärdare. Kubernetes
API fortsätter använda ServiceAccountets egen CA separat.

Kontrollera efter applicering:

```sh
oc get configmap cvebridge-trusted-ca
oc rollout status deployment/cvebridge
```

`DATA` ska bli `1` när OpenShift lagt in `ca-bundle.crt`. Om poden väntar på
filen kontrollerar plattformsteamet CA-injektionen. Ett fyllt paket visar att
injektionen fungerar; testa även `/cve status` och `/cve scan team-a` för att
kontrollera de riktiga HTTPS-anslutningarna.

Lägg injiceringsetiketten **bara på den separata CA-ConfigMapen**. OpenShift
tar över dess innehåll; etiketten får aldrig sättas på `cvebridge-config`,
eftersom botens inställningar då skulle raderas.

Efter CA-förnyelse startar du om boten för att läsa det uppdaterade paketet:

```sh
oc rollout restart deployment/cvebridge
oc rollout status deployment/cvebridge
```

Ingen ny image eller privat certifikatnyckel behövs. Detta konfigurerar botens
utgående HTTPS. Podman på byggdatorn och Mattermost-servern behöver själva lita
på certifikaten för registryt respektive botens route.

### Om rätt företags-CA saknas i klusterpaketet

Be plattformsteamet kontrollera paketet. Om ni behöver en separat fil kan
systemansvarig lämna den publika CA-kedjan i PEM-format. Spara den lokalt som
`certs/foretags-ca.pem` och skapa en annan ConfigMap:

```sh
oc create configmap cvebridge-extra-ca --from-file=ca.pem=certs/foretags-ca.pem --dry-run=client -o yaml | oc apply -f -
```

Lägg till detta i Deployment under `spec.template.spec.volumes`:

```yaml
- name: extra-ca
  configMap:
    name: cvebridge-extra-ca
```

Lägg till under containerns `volumeMounts`:

```yaml
- name: extra-ca
  mountPath: /ca-extra
  readOnly: true
```

Ändra `STACKROX_CA_FILE` till `/ca-extra/ca.pem` i `deploy/app/configmap.yaml`
om filen gäller ACS. Ändra även `MATTERMOST_CA_FILE` om samma CA gäller där.
En annan Mattermost-CA kan inkluderas som ytterligare fil i samma ConfigMap;
ange då dess filnamn i `MATTERMOST_CA_FILE`. Behåll alla `--from-file`-argument
i samma kommando. Ändra aldrig innehållet manuellt i `cvebridge-trusted-ca`.

Applicera extra-CA, appens ConfigMap och Deployment, och starta om boten.
Go-boten lägger de angivna CA-certifikaten till imagens befintliga betrodda
certifikat. TLS-verifiering av certifikatkedja och värdnamn är alltid aktiv.

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
[OpenShift CA-injektion](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators),
[Kubernetes ConfigMap-volym](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/).
