package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

func originImage(t *testing.T) M {
	t.Helper()
	data, err := os.ReadFile("testdata/acs-image-origin.json")
	if err != nil {
		t.Fatal(err)
	}
	var image M
	if err := json.Unmarshal(data, &image); err != nil {
		t.Fatal(err)
	}
	return image
}

func testImageSummary(t *testing.T) M {
	t.Helper()
	image := originImage(t)
	summary := M{"imageId": image["id"], "image": "registry.example.test/demo/app-python:v1", "targets": []any{
		M{"namespace": "team-b", "image": "registry.example.test/demo/app-python:v1"},
		M{"namespace": "team-a", "image": "registry.example.test/demo/app-python:v1"},
		M{"namespace": "team-a", "image": "registry.example.test/demo/app-python:v1"},
	}}
	addImageSummary(summary, image, true)
	return summary
}

func TestACSImageSummaryKeepsNativeSeverityAndVerifiedLayerOrigin(t *testing.T) {
	summary := testImageSummary(t)
	// This stripped, real ACS 4.11.6 response has different native severity
	// totals than a CVSS-only reclassification. Base aliases share a digest.
	counts := obj(summary["findings"])
	for category, want := range map[string]int{"critical": 4, "high": 16, "other": 38, "unknown": 1, "total": 59} {
		if int(num(counts[category])) != want {
			t.Errorf("native ACS %s = %v, want %d", category, counts[category], want)
		}
	}
	if num(obj(summary["baseFindings"])["total"]) != 56 || len(arr(summary["applicationComponents"])) != 1 || len(arr(summary["unknownComponents"])) != 0 {
		t.Fatal("base/application boundary must include empty history layers", summary)
	}
	cells := applicationCells(summary)
	if len(cells) != 1 || !strings.Contains(cells[0], "65.5.0") || !strings.Contains(cells[0], "83.0.0") || strings.Contains(cells[0], "78.1.1") {
		t.Fatal("package target must use the ACS component-wide fix", cells)
	}
	text := str(ResultMessage(M{"kind": "scan", "images": []any{summary}})["text"])
	if strings.Count(text, "| `team-a` |") != 1 || strings.Count(text, "| `team-b` |") != 1 {
		t.Fatal("one row per namespace/image, despite repeated workloads", text)
	}
	for _, excluded := range []string{"Workload", "JSON", "Rekommenderad", "3.13.18", "@channel"} {
		if strings.Contains(text, excluded) {
			t.Fatal("unrequested content or invented update in table", excluded, text)
		}
	}
	if !strings.Contains(text, "delvis underlag") || !strings.Contains(text, "1 ej bedömda") {
		t.Fatal("incomplete coverage and unknown severity must remain visible", text)
	}
}

func TestImageSummaryDoesNotRetainRawVulnerabilitiesAcrossCluster(t *testing.T) {
	for _, matched := range []bool{false, true} {
		image := originImage(t)
		if !matched {
			delete(image, "baseImageInfo")
		}
		for _, raw := range arr(obj(image["scan"])["components"]) {
			for _, vuln := range arr(obj(raw)["vulns"]) {
				obj(vuln)["summary"] = "raw-advisory-marker"
			}
		}
		summary := M{}
		addImageSummary(summary, image, true)
		if strings.Contains(encode(summary), "raw-advisory-marker") || strings.Contains(encode(summary), `"vulns"`) || num(obj(summary["findings"])["total"]) != 59 {
			t.Fatal("image table summary retained raw advisory objects or changed counts")
		}
		if !matched && num(obj(summary["unknownFindings"])["total"]) != 59 {
			t.Fatal("unknown-origin findings must remain counted without retaining every vulnerability")
		}
		if matched {
			cells := strings.Join(applicationCells(summary), "; ")
			if !strings.Contains(cells, "setuptools") || !strings.Contains(cells, "65.5.0") || !strings.Contains(cells, "83.0.0") {
				t.Fatal("compaction lost affected package or fix information", cells)
			}
		}
	}
}

func TestUnknownOrAmbiguousBaseDoesNotAttributePackagesToApp(t *testing.T) {
	for _, variant := range []string{"absent", "ambiguous", "missing-index", "outside-history"} {
		t.Run(variant, func(t *testing.T) {
			image := originImage(t)
			bases := arr(image["baseImageInfo"])
			switch variant {
			case "absent":
				delete(image, "baseImageInfo")
			case "ambiguous":
				obj(bases[1])["baseImageDigest"] = "sha256:" + strings.Repeat("f", 64)
			case "missing-index":
				for _, base := range bases {
					delete(obj(base), "maxLayerIndex")
				}
			case "outside-history":
				for _, base := range bases {
					obj(base)["maxLayerIndex"] = 1000
				}
			}
			summary := M{}
			addImageSummary(summary, image, true)
			if len(obj(summary["base"])) != 0 || len(arr(summary["applicationComponents"])) != 0 || len(arr(summary["unknownComponents"])) != 62 {
				t.Fatal("unverified origin was assigned to application or base")
			}
			if got := strings.Join(applicationCells(summary), ""); got != "Ursprung ej verifierat" {
				t.Fatal(got)
			}
		})
	}
	image := originImage(t)
	parts := arr(obj(image["scan"])["components"])
	delete(obj(parts[len(parts)-1]), "layerIndex")
	summary := M{}
	addImageSummary(summary, image, false)
	if len(arr(summary["unknownComponents"])) != 1 || len(arr(summary["applicationComponents"])) != 0 {
		t.Fatal("absent package layer index must not default to base layer zero")
	}
}

func TestImageTablesKeepAllNamespacesAndAllAffectedAppPackages(t *testing.T) {
	summary := testImageSummary(t)
	apps := []any{}
	for i := 0; i < 40; i++ {
		apps = append(apps, M{"name": fmt.Sprintf("app-package-%02d", i), "version": "1.0", "fixedBy": "2.0", "vulns": []any{M{"cve": "CVE-2026-12345", "severity": "IMPORTANT_VULNERABILITY_SEVERITY"}}})
	}
	summary["applicationComponents"] = apps
	targets := []any{}
	for i := 0; i < 100; i++ {
		targets = append(targets, M{"namespace": fmt.Sprintf("team-%03d", i), "image": "registry.example.test/demo/app-python:v1"})
	}
	summary["targets"] = targets
	posts := imageReportMessages(M{"images": []any{summary}, "alertCves": []string{"CVE-2026-12345"}})
	all := ""
	for _, post := range posts {
		text := str(post["text"])
		table := text[strings.Index(text, "| "):]
		if utf8.RuneCountInString(text) > 16383 || strings.Count(table, "\n|") > 7 || post["attachments"] != nil {
			t.Fatal("table not split into bounded native posts")
		}
		all += text + "\n"
	}
	if strings.Count(all, "@channel") != 1 {
		t.Fatal("only the first table page may ping the channel")
	}
	for i := 0; i < 100; i++ {
		if !strings.Contains(all, fmt.Sprintf("`team-%03d`", i)) {
			t.Fatal("namespace omitted", i)
		}
	}
	for i := 0; i < 40; i++ {
		if strings.Count(all, fmt.Sprintf("`app-package-%02d`", i)) != 100 {
			t.Fatal("affected package silently omitted", i)
		}
	}
}

func TestFailedScanIsUnknownRatherThanZeroFindings(t *testing.T) {
	summary := testImageSummary(t)
	summary["status"] = "failed"
	text := str(imageReportMessages(M{"images": []any{summary}})[0]["text"])
	if !strings.Contains(text, "Underlag saknas") || strings.Contains(text, "0 kända fynd") || strings.Contains(text, "setuptools") {
		t.Fatal("failed scan presented as a clean or scanned image", text)
	}
}

func TestPackageTargetsAreNotGuessedFromAdvisoryVersionOrdering(t *testing.T) {
	summary := testImageSummary(t)
	part := obj(arr(summary["applicationComponents"])[0])
	delete(part, "fixedBy")
	text := strings.Join(applicationCells(summary), "; ")
	if !strings.Contains(text, "olika fixversioner per CVE") || strings.Contains(text, "→") {
		t.Fatal("multiple advisory versions must not be compared lexically", text)
	}
}

func TestPartialTableDeliveryDoesNotAdvanceAlertState(t *testing.T) {
	f := newFixture(t)
	original := f.Server.Config.Handler
	var posts atomic.Int32
	f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/posts" && posts.Add(1) == 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		original.ServeHTTP(w, r)
	})
	summary := testImageSummary(t)
	targets := []any{}
	for i := 0; i < 7; i++ {
		targets = append(targets, M{"namespace": "team-a", "image": fmt.Sprintf("registry.example.test/demo/app-python:v%d", i)})
	}
	summary["targets"] = targets
	result := M{"kind": "scan", "namespaces": []string{"team-a"}, "images": []any{summary}, "rows": []any{M{"namespace": "team-a", "cve": "CVE-2026-12345", "cvss": 9.8}}}
	if _, err := f.App.Store.Publish(context.Background(), f.App.S, channelID, result); err == nil {
		t.Fatal("partially delivered table accepted")
	}
	var count int
	if err := f.App.Store.DB.QueryRow("SELECT COUNT(*) FROM cve_seen").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial delivery consumed CVE notification", count, err)
	}
}

func TestTablePagesRecheckAuthorization(t *testing.T) {
	f := newFixture(t)
	summary := testImageSummary(t)
	targets := []any{}
	for i := 0; i < 7; i++ {
		targets = append(targets, M{"namespace": "team-a", "image": fmt.Sprintf("registry.example.test/app:v%d", i)})
	}
	summary["targets"] = targets
	checks := 0
	_, err := f.App.S.Post(context.Background(), channelID, M{"kind": "scan", "images": []any{summary}}, func() error {
		checks++
		if checks == 2 {
			return problem(403, "Channel membership changed")
		}
		return nil
	})
	if err == nil || checks != 2 || len(f.Posts) != 1 {
		t.Fatal("table continued after authorization was revoked", err, checks, len(f.Posts))
	}
}

func TestImageTableFallsBackWhenInlineLatexIsDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			f := newFixture(t)
			original := f.Server.Config.Handler
			f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v4/config/client" {
					writeJSON(w, 200, M{"EnableInlineLatex": fmt.Sprint(enabled)})
					return
				}
				original.ServeHTTP(w, r)
			})
			_, err := f.App.S.Post(context.Background(), channelID, M{"kind": "scan", "images": []any{testImageSummary(t)}})
			if err != nil || len(f.Posts) != 1 {
				t.Fatal(err)
			}
			if strings.Contains(str(f.Posts[0]["message"]), `\textcolor`) != enabled {
				t.Fatal("header style does not match server capabilities")
			}
		})
	}
}
