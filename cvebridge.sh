#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
engine=${CONTAINER_ENGINE:-docker}
action=${1:-help}
if [ "$action" = init ]; then
  if [ -e .env ]; then printf '%s\n' '.env already exists; keeping your values.'; exit 0; fi
  (umask 077; cp .env.example .env)
  printf '%s\n' 'Created .env. Fill in your company values, then run build, push and render.'
  exit 0
fi
if [ ! -f .env ]; then printf '%s\n' 'Run ./cvebridge.sh init first.' >&2; exit 1; fi
# Read ONLY an image name as data. Never source .env or evaluate its contents.
image=$(awk -F= '$1 == "APP_IMAGE" {sub(/^[^=]*=/, ""); print; n++} END {if(n!=1) exit 1}' .env)
case "$image" in ''|*[!a-zA-Z0-9._:/@-]*) printf '%s\n' 'APP_IMAGE must be an unquoted registry/image:tag or digest.' >&2; exit 1;; esac
case "$action" in
  build) "$engine" build --build-arg "VERSION=$(git rev-parse --short HEAD 2>/dev/null || printf local)" -t "$image" . ;;
  push) "$engine" push "$image" ;;
  render)
    mkdir -p deploy/generated
    umask 077
    for part in deployment bootstrap; do
      output="deploy/generated/$part.yaml"
      temporary="$output.tmp"
      if "$engine" run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace:ro" -w /workspace "$image" render --env-file /workspace/.env --part "$part" > "$temporary"; then
        mv "$temporary" "$output"
      else rm -f "$temporary"; exit 1; fi
    done
    printf '%s\n' 'Generated deploy/generated/bootstrap.yaml and deployment.yaml (contains secrets; do not commit).'
    ;;
  *) printf '%s\n' 'Usage: ./cvebridge.sh init|build|push|render' ;;
esac
