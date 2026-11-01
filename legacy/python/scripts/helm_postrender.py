#!/usr/bin/env python3
"""Local-only StackRox chart overlay, using kubectl's bundled Kustomize.

Persist the upstream vulnerability database and give its initial index build a
larger memory budget. Keep the scanner's disposable index in memory to avoid
millions of small disk writes during startup. An interrupted first import is
rebuilt from the genuine upstream dump, never mistaken for a complete database.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


INIT = r'''set -eu
DATA=/var/lib/postgresql/data
if [ -f "$DATA/.cvebridge-initialized" ]; then
  exit 0
fi
# This PVC contains only this lab's regenerable scanner cache. If a previous
# import failed, PG_VERSION alone is not evidence that all data/indexes exist.
for item in "$DATA"/* "$DATA"/.[!.]* "$DATA"/..?*; do
  if [ -e "$item" ] || [ -L "$item" ]; then rm -rf -- "$item"; fi
done
export PGOPTIONS='-c maintenance_work_mem=1024MB'
/usr/local/bin/docker-entrypoint.sh postgres -c config_file=/etc/postgresql.conf
touch "$DATA/.cvebridge-initialized"
'''


def main():
    patch = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "scanner-db"},
             "spec": {"template": {"spec": {
                 "initContainers": [{"name": "init-db", "command": ["/bin/sh", "-c"], "args": [INIT]}],
                 "volumes": [{"name": "scanner-db-data", "emptyDir": None,
                              "persistentVolumeClaim": {"claimName": "cvebridge-scanner-db"}}]}}}}
    cache_patch = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "scanner"},
                   "spec": {"template": {"spec": {"volumes": [{"name": "vuln-temp-db",
                       "emptyDir": {"medium": "Memory", "sizeLimit": "3Gi"}}]}}}}
    with tempfile.TemporaryDirectory(prefix="cvebridge-render-") as directory:
        path = Path(directory)
        manifest = path/"all.yaml"
        manifest.write_text(sys.stdin.read())
        manifest.chmod(0o600)
        (path/"kustomization.yaml").write_text(json.dumps({"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
                       "resources": ["all.yaml"], "patches": [
                           {"target": {"group": "apps", "version": "v1", "kind": "Deployment", "name": "scanner-db"}, "patch": json.dumps(patch)},
                           {"target": {"group": "apps", "version": "v1", "kind": "Deployment", "name": "scanner"}, "patch": json.dumps(cache_patch)}]}))
        subprocess.run(["kubectl", "kustomize", directory], stdout=sys.stdout, stderr=sys.stderr, check=True)


if __name__ == "__main__":
    main()
