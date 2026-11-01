#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
engine=${CONTAINER_ENGINE:-docker}
action=${1:-help}
if [ "$action" = init ]; then
  if [ -e .env ]; then printf '%s\n' '.env finns redan; dina värden behålls.'; exit 0; fi
  (umask 077; cp .env.example .env)
  printf '%s\n' 'Skapade .env. Fyll i företagsvärdena och logga in med oc.'
  exit 0
fi
case "$action" in build|push|render|image) ;; *) printf '%s\n' 'Användning: ./cvebridge.sh init|build|push|render|image'; exit 0;; esac
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
  printf '%s\n' 'NAMESPACE måste vara ett giltigt namespace.' >&2; exit 1
fi
image=$(field APP_IMAGE)
if [ -z "$image" ]; then
  tag=$(field IMAGE_TAG)
  if [ -z "$tag" ]; then
    revision=$(git rev-parse --short HEAD 2>/dev/null || true)
    if [ -z "$revision" ]; then
      revision=$(cksum Dockerfile go.mod go.sum cvebridge.sh cmd/cvebridge/*.go internal/bridge/*.go | cksum | awk '{print $1}')
    fi
    tag="go-$revision"
  fi
  if ! printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'; then
    printf '%s\n' 'IMAGE_TAG måste vara en giltig image-tagg.' >&2; exit 1
  fi
  image="image-registry.openshift-image-registry.svc:5000/$namespace/cvebridge:$tag"
fi
case "$image" in ''|*[!a-zA-Z0-9._:/@-]*) printf '%s\n' 'Ogiltig APP_IMAGE.' >&2; exit 1;; esac
case "$action" in
  image) printf '%s\n' "$image" ;;
  build) "$engine" build --build-arg "VERSION=${image##*:}" -t "$image" . ;;
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
        registry=$(field REGISTRY_PUSH_HOST)
        if [ -z "$registry" ]; then
          if ! registry=$(oc get route default-route -n openshift-image-registry -o 'jsonpath={.spec.host}'); then
            printf '%s\n' 'Kunde inte läsa registry-routen. Ange REGISTRY_PUSH_HOST i .env om plattformsteamet ger dig en annan adress eller du saknar läsbehörighet.' >&2; exit 1
          fi
        fi
        case "$registry" in ''|*[!a-zA-Z0-9.:-]*) printf '%s\n' 'Ogiltig eller tom registry-route.' >&2; exit 1;; esac
        oc whoami -t | "$engine" login --username cvebridge --password-stdin "$registry"
        push_image="$registry/$repository"
        "$engine" tag "$image" "$push_image"
        "$engine" push "$push_image"
        ;;
      *) "$engine" push "$image" ;;
    esac
    ;;
  render)
    mkdir -p deploy/generated
    umask 077
    for part in deployment bootstrap; do
      output="deploy/generated/$part.yaml"
      temporary="$output.tmp"
      if "$engine" run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace:ro" -w /workspace "$image" render --env-file /workspace/.env --image "$image" --part "$part" > "$temporary"; then
        mv "$temporary" "$output"
      else rm -f "$temporary"; exit 1; fi
    done
    printf '%s\n' 'Skapade deploy/generated/bootstrap.yaml och deployment.yaml. Filerna är privata och ska inte committas.'
    webhook=$(field WEBHOOK_URL)
    if [ -z "$webhook" ]; then webhook=$(field WEBHOOK_PUBLIC_URL); fi
    webhook=${webhook:-http://cvebridge-webhook.$namespace.svc:8001}
    printf 'Mattermost Request URL: %s/slash/cve\n' "$webhook"
    ;;
esac
