package bridge

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

func TestImageOriginDiagnosticsExplainUnverifiedDataAtInfo(t *testing.T) {
	for _, test := range []struct {
		reason string
		change func(M)
	}{
		{"verified", func(M) {}},
		{"no_base_image_match", func(image M) { delete(image, "baseImageInfo") }},
		{"missing_layer_history", func(image M) { delete(image, "metadata") }},
		{"invalid_base_image_match", func(image M) {
			for _, base := range arr(image["baseImageInfo"]) {
				obj(base)["maxLayerIndex"] = 10000
			}
		}},
		{"ambiguous_base_image_match", func(image M) {
			obj(arr(image["baseImageInfo"])[1])["baseImageDigest"] = "sha256:" + strings.Repeat("f", 64)
		}},
		{"component_layer_index_unavailable", func(image M) {
			parts := arr(obj(image["scan"])["components"])
			delete(obj(parts[0]), "layerIndex")
			obj(parts[1])["layerIndex"] = -1
			obj(parts[2])["layerIndex"] = 10000
		}},
	} {
		t.Run(test.reason, func(t *testing.T) {
			f := newFixture(t)
			image := originImage(t)
			image["id"] = imageDigest
			obj(image["scan"])["scanTime"] = time.Now().UTC().Format(time.RFC3339Nano)
			image["unused-private-field"] = "raw-response-marker"
			test.change(image)
			f.ImageResponse = image
			f.App.S.C.Env["LOG_LEVEL"] = "info"
			var output bytes.Buffer
			f.App.S.debugLogger = log.New(&output, "", 0)
			result, err := f.App.S.Scan(context.Background(), []string{"team-a"}, func() error { return nil }, false, false)
			if err != nil || num(result["scannedImages"]) != 1 {
				t.Fatal("origin diagnostics must not reject a usable scan", result, err)
			}
			entries := debugEntries(t, &output)
			var origins []M
			for _, entry := range entries {
				if str(entry["event"]) == "image_origin" {
					origins = append(origins, entry)
				}
			}
			if len(origins) != 1 || str(origins[0]["reason"]) != test.reason || str(origins[0]["hint"]) == "" {
				t.Fatal("missing actionable per-image origin reason", output.String())
			}
			entry := origins[0]
			if test.reason == "verified" && (num(entry["base_components"]) != 61 || num(entry["application_components"]) != 1 || num(entry["unknown_components"]) != 0) {
				t.Fatal("verified counts must match real ACS fixture", entry)
			}
			if test.reason == "component_layer_index_unavailable" && (num(entry["missing_component_layer_index"]) != 1 || num(entry["invalid_component_layer_index"]) != 1 || num(entry["out_of_range_component_layer_index"]) != 1) {
				t.Fatal("invalid package indices must have separate diagnostic counts", entry)
			}
			if strings.Contains(output.String(), "raw-response-marker") || strings.Contains(output.String(), "[ACS DEBUG]") {
				t.Fatal("origin info must omit raw response and keep debug disabled")
			}
			for key, value := range f.App.S.C.Env {
				if value != "" && strings.Contains(key, "TOKEN") && strings.Contains(output.String(), value) {
					t.Fatal("origin diagnostic revealed a credential")
				}
			}
		})
	}
}
