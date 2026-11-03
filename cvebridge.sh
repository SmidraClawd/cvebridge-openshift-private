#!/bin/sh
# Legacy helper. Manual installation uses the checked-in deploy/ files.
# Generated manifests stay under deploy/local/ and never replace those files.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
engine=${CONTAINER_ENGINE:-podman}
action=${1:-help}
case "$action" in
  init)
    if [ -e .env ]; then printf '%s\n' '.env finns redan; dina värden behålls.'; exit 0; fi
    (umask 077; cp .env.example .env)
    printf '%s\n' 'Skapade .env. Fyll i era värden.'
    exit 0 ;;
  build)
    revision=$(git rev-parse --short HEAD 2>/dev/null || true)
    revision=${revision:-local}
    "$engine" build --build-arg "VERSION=go-$revision" -t cvebridge:local .
    exit 0 ;;
  push|render|image) ;;
  *) printf '%s\n' 'Användning: ./cvebridge.sh init|build|push|render|image'; exit 0 ;;
esac
if [ ! -f .env ]; then printf '%s\n' 'Kör ./cvebridge.sh init först.' >&2; exit 1; fi
# Read a few scalar fields as literal data. Never source/evaluate .env.
field() {
  awk -v wanted="$1" '
    /^[[:space:]]*#/ {next}
    {
      pos=index($0,"="); if(!pos) next
      key=substr($0,1,pos-1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",key)
      if(key!=wanted) next
      value=substr($0,pos+1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",value)
      quote=substr(value,1,1)
      if(quote=="\047" || quote=="\042") {
        if(length(value)<2 || substr(value,length(value),1)!=quote) exit 2
        value=substr(value,2,length(value)-2)
      }
      result=value; n++
    }
    END {if(n>1) exit 2; if(n==1) print result}
  ' .env
}

namespace=$(field NAMESPACE)
namespace=${namespace:-cvebridge}
if ! printf '%s\n' "$namespace" | LC_ALL=C grep -Eq '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'; then
  printf '%s\n' 'Fyll i ett giltigt NAMESPACE i .env.' >&2; exit 1
fi
if ! local_id=$("$engine" image inspect --format '{{.Id}}' cvebridge:local); then
  printf 'Bygg först: %s build -t cvebridge:local .\n' "$engine" >&2; exit 1
fi
case "$local_id" in sha256:*) digest=${local_id#sha256:};; *) printf '%s\n' 'Kunde inte läsa den lokala imagen.' >&2; exit 1;; esac
if ! printf '%s\n' "$digest" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$'; then
  printf '%s\n' 'Ogiltigt lokalt image-ID.' >&2; exit 1
fi
image=$(field APP_IMAGE)
if [ -z "$image" ]; then
  tag=$(field IMAGE_TAG)
  tag=${tag:-go-$(printf '%.12s' "$digest")}
  if ! printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'; then
    printf '%s\n' 'IMAGE_TAG måste vara en giltig image-tagg.' >&2; exit 1
  fi
  image="image-registry.openshift-image-registry.svc:5000/$namespace/cvebridge:$tag"
fi
case "$image" in ''|*[!a-zA-Z0-9._:/@-]*) printf '%s\n' 'Ogiltig APP_IMAGE.' >&2; exit 1;; esac
render_manifests() {
  (umask 077; mkdir -p deploy/local)
  "$engine" run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace:ro" -v "$PWD/deploy/local:/output:rw" -w /workspace cvebridge:local render --env-file /workspace/.env --image "$image" --output-dir /output
  printf '%s\n' 'Skapade deploy/local/bootstrap.yaml och YAML-filer i deploy/local/app/.'
  webhook=$(field WEBHOOK_URL)
  if [ -z "$webhook" ]; then webhook=$(field WEBHOOK_PUBLIC_URL); fi
  webhook=${webhook:-http://cvebridge-webhook.$namespace.svc:8001}
  printf 'Mattermost Request URL: %s/slash/cve\n' "$webhook"
}
case "$action" in
  image) printf '%s\n' "$image" ;;
  render) render_manifests ;;
  push)
    case "$image" in
      image-registry.openshift-image-registry.svc:5000/*)
        repository=${image#image-registry.openshift-image-registry.svc:5000/}
        project=${repository%%/*}
        if [ "$project" != "$namespace" ] || [ "${repository#*/}" = "$repository" ]; then
          printf '%s\n' 'Registry-projektet måste vara samma som NAMESPACE.' >&2; exit 1
        fi
        case "${repository#*/}" in */*) printf '%s\n' 'OpenShift använder namespace/image:tag, utan fler undermappar.' >&2; exit 1;; esac
        oc whoami >/dev/null
        oc get project "$namespace" -o name >/dev/null
        existing_claim=$(field STATE_EXISTING_PVC)
        if [ -n "$existing_claim" ]; then oc get pvc "$existing_claim" -n "$namespace" -o name >/dev/null; fi
        render_manifests
        registry=$(field REGISTRY_PUSH_HOST)
        if [ -z "$registry" ]; then
          if ! registry=$(oc get route default-route -n openshift-image-registry -o 'jsonpath={.spec.host}'); then
            printf '%s\n' 'Kunde inte läsa registry-routen. Ange REGISTRY_PUSH_HOST från plattformsteamet i .env.' >&2; exit 1
          fi
        fi
        case "$registry" in ''|*[!a-zA-Z0-9.:-]*) printf '%s\n' 'Ogiltig eller tom registry-adress.' >&2; exit 1;; esac
        oc whoami -t | "$engine" login --username cvebridge --password-stdin "$registry"
        push_image="$registry/$repository"
        "$engine" tag cvebridge:local "$push_image"
        "$engine" push "$push_image"
        ;;
      *)
        render_manifests
        "$engine" tag cvebridge:local "$image"
        "$engine" push "$image" ;;
    esac
    printf 'Klart. Deployment använder %s\n' "$image"
    printf '%s\n' 'Legacy-utdata: deploy/local/. Se README för manuell installation med deploy/.'
    ;;
esac
