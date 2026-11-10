package bridge

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func largeInventory(t *testing.T, records, active, images int, settings map[string]string) (*Services, *bytes.Buffer) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pods":
			if r.URL.Query().Get("query") != `Cluster ID:"cluster-123"` {
				t.Error("cluster-wide query must keep its exact cluster restriction", r.URL.Query())
			}
			offset, _ := strconv.Atoi(r.URL.Query().Get("pagination.offset"))
			page := []M{}
			for i := offset; i < records && i < offset+100; i++ {
				page = append(page, M{"id": fmt.Sprintf("pod-%d", i), "namespace": fmt.Sprintf("team-%d", i%3), "clusterId": "cluster-123",
					"deploymentId":  fmt.Sprintf("dep-%d-%d", i%3, i%images),
					"liveInstances": []M{{"containerName": "main", "imageDigest": fmt.Sprintf("sha256:%064x", i%images+1), "finished": i >= active}}})
			}
			writeJSON(w, 200, M{"pods": page})
		default:
			var ns, image int
			if n, err := fmt.Sscanf(r.URL.Path, "/v1/deployments/dep-%d-%d", &ns, &image); n != 2 || err != nil {
				t.Error("inventory must finish before any image reads or scans", r.URL.Path)
				writeJSON(w, 500, M{})
				return
			}
			writeJSON(w, 200, M{"name": fmt.Sprintf("app-%d", image), "namespace": fmt.Sprintf("team-%d", ns), "clusterId": "cluster-123",
				"containers": []M{{"name": "main", "image": M{"id": fmt.Sprintf("sha256:%064x", image+1),
					"name": M{"fullName": fmt.Sprintf("registry.acme.test/app-%d:latest", image)}}}}})
		}
	}))
	t.Cleanup(server.Close)
	env := map[string]string{"ACCESS_MODE": "operations", "STACKROX_URL": server.URL, "STACKROX_CLUSTER_ID": "cluster-123", "STACKROX_TOKEN": "private-credential", "LOG_LEVEL": "info"}
	for k, v := range settings {
		env[k] = v
	}
	output := &bytes.Buffer{}
	return &Services{C: Config{Env: env}, Rox: server.Client(), debugLogger: log.New(output, "", 0)}, output
}

func TestClusterInventoryPassesAllThreeFormerLimits(t *testing.T) {
	s, output := largeInventory(t, 10501, 2001, 101, nil)
	inv, err := s.Inventory(context.Background(), []string{"*"}, false)
	if err != nil || len(inv.Images) != 101 || inv.Pods != 2001 || inv.Records != 10501 {
		t.Fatal("cluster inventory must pass the former image/pod/pagination limits without dropping results", inv.Pods, inv.Records, len(inv.Images), err)
	}
	for _, image := range inv.Images {
		if len(image.Targets) != 3 {
			t.Fatal("shared image lost a namespace", image)
		}
	}
	if !strings.Contains(output.String(), `"max_images":1000`) || !strings.Contains(output.String(), `"event":"inventory_progress"`) {
		t.Fatal("active inventory limits and progress must be visible at info", output.String())
	}
}

func TestInventoryLimitsReportExactReasonBeforeAnyImageScan(t *testing.T) {
	for _, test := range []struct {
		key                                   string
		limit, count, records, active, images int
	}{
		{"SCAN_MAX_IMAGES", 100, 101, 101, 101, 101},
		{"SCAN_MAX_PODS", 2, 3, 3, 3, 1},
		{"SCAN_MAX_POD_RECORDS", 100, 101, 101, 0, 1},
	} {
		t.Run(test.key, func(t *testing.T) {
			s, output := largeInventory(t, test.records, test.active, test.images, map[string]string{test.key: strconv.Itoa(test.limit)})
			result, err := s.Scan(context.Background(), []string{"*"}, func() error { return nil }, true, false)
			if err == nil || result != nil || !strings.Contains(message(err), test.key) || !strings.Contains(message(err), strconv.Itoa(test.count)) {
				t.Fatal("limit must identify its count, setting and remedy instead of a generic selection error", result, err)
			}
			var found M
			for _, entry := range debugEntries(t, output) {
				if str(entry["event"]) == "inventory_limit" {
					found = entry
				}
			}
			if str(found["setting"]) != test.key || int(num(found["count"])) != test.count || int(num(found["limit"])) != test.limit || str(found["hint"]) == "" {
				t.Fatal("exact inventory failure must be visible at info", output.String())
			}
			if strings.Contains(output.String(), "private-credential") {
				t.Fatal("inventory diagnostic leaked a token")
			}
		})
	}
}

func TestInventoryAcceptsExactLimitIncludingFinalEmptyPage(t *testing.T) {
	s, output := largeInventory(t, 100, 100, 2, map[string]string{"SCAN_MAX_IMAGES": "2", "SCAN_MAX_PODS": "100", "SCAN_MAX_POD_RECORDS": "100"})
	inv, err := s.Inventory(context.Background(), []string{"*"}, false)
	if err != nil || inv.Records != 100 || inv.Pods != 100 || len(inv.Images) != 2 || strings.Contains(output.String(), "inventory_limit") {
		t.Fatal("exactly reaching a limit must not reject the final empty pagination page", inv, err)
	}
}

func TestInventoryLimitConfigurationValidatesOptionalOverrides(t *testing.T) {
	for _, test := range []struct {
		key, largest, tooLarge string
	}{
		{"SCAN_MAX_IMAGES", "10000", "10001"},
		{"SCAN_MAX_PODS", "100000", "100001"},
		{"SCAN_MAX_POD_RECORDS", "1000000", "1000001"},
	} {
		for _, value := range []string{"", "0", "-1", "1.5", "no", test.tooLarge, "99999999999999999999999999"} {
			env := shortEnv()
			env[test.key] = value
			if _, err := NewConfig(env); err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatal("invalid inventory budget was accepted or not identified", test.key, value, err)
			}
		}
		env := shortEnv()
		env[test.key] = test.largest
		if _, err := NewConfig(env); err != nil {
			t.Fatal("valid optional budget rejected", test.key, err)
		}
	}
}
