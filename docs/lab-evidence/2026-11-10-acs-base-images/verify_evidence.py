"""Read-only consistency check of archived ACS results; no live API calls."""

import hashlib
import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(relative):
    return json.loads((ROOT / relative).read_text())


def main():
    manifest = read("source-manifest.json")
    assert len(manifest) == 81
    for item in manifest:
        raw = (ROOT / item["archivePath"]).read_bytes()
        if item["compression"] == "gzip":
            raw = gzip.decompress(raw)
        assert len(raw) == item["size"], item["sourcePath"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"], item["sourcePath"]
    bundle = read("outputs/acs-aldre-basimages-bevis.json")
    state = bundle["test"]
    assert state == read("work/late-base-detection/run.json")
    assert state["acsMetadata"]["version"] == "4.11.6"
    assert len(state["assertions"]) == 17
    assert len(state["cases"]) == 2

    def rows(label):
        return {row["minor"]: row for row in state[label]}

    before = rows("baseline")
    first = rows("after-https-311")
    final = rows("after-https-both")
    assert all(not row["baseMatches"] for row in before.values())
    assert not first["3.10"]["baseMatches"]
    assert len(first["3.11"]["baseMatches"]) == 1
    assert all(not row["baseMatches"] for row in bundle["nativeBefore"]["images"])
    assert all(not row["baseMatches"] for row in bundle["nativeAfterFirstRegistrationBeforeRescan"]["images"])

    for case in state["cases"]:
        minor = case["minor"]
        short = minor.replace(".", "")
        app = case["appManifest"]
        base = case["mirroredBase"]
        assert case["appBuildFinished"] < state["secureRegistrationRequestedAt"]
        assert before[minor]["appDigest"] == final[minor]["appDigest"] == app["manifestDigest"]
        assert before[minor]["appConfigDigest"] == final[minor]["appConfigDigest"] == app["configDigest"]
        assert len(app["layers"]) > len(base["layers"])
        assert app["layers"][: len(base["layers"])] == base["layers"]
        matches = final[minor]["baseMatches"]
        assert len(matches) == 1
        assert matches[0]["baseImageDigest"] == base["manifestDigest"]
        assert matches[0]["baseImageFullName"].endswith(":" + case["tag"])
        native = next(row for row in bundle["nativeFinal"]["images"] if row["id"] == app["manifestDigest"])
        assert native["baseMatches"] == matches
        assert native["metadataLayers"] == app["layers"]
        source = next(row for row in state["secureSourceVerification"] if row["minor"] == minor)
        assert source["manifestDigest"] == base["manifestDigest"]
        assert source["layers"] == base["layers"]
        for phase in ("baseline", "after-https-311", "after-https-both"):
            raw = read(f"work/late-base-detection/{phase}-python-{short}.json")
            assert raw["id"] == app["manifestDigest"]
            assert raw["metadata"]["v1"]["digest"] == app["configDigest"]
            assert raw["metadata"]["layerShas"] == app["layers"]
            assert raw.get("baseImageInfo", []) == rows(phase)[minor]["baseMatches"]

    assert read("work/late-base-detection/references-before.json") == read("work/late-base-detection/references-after-cleanup.json")
    cleanup = state["cleanup"]
    assert cleanup["testNamespaceRemoved"]
    assert cleanup["originalReferencesUnchanged"]
    assert cleanup["originalDeploymentsUnchanged"]
    evidence_hash = hashlib.sha256((ROOT / "outputs/acs-aldre-basimages-bevis.json").read_bytes()).hexdigest()
    assert evidence_hash in (ROOT / "outputs/acs-aldre-basimages-test.txt").read_text()
    print("PASS: saved ACS evidence, immutable image digests, negative control and cleanup records agree.")
    print("This is an offline evidence check, not a new live integration test.")


if __name__ == "__main__":
    main()
