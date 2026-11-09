package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestInventoryExcludesNamespacesAndClustersWithSamePrefix(t *testing.T) {
	const namespace = "ocp-api"
	const clusterID = "cluster-123"
	pods := []M{
		{"id": "wanted", "namespace": namespace, "clusterId": clusterID, "deploymentId": "dep1", "liveInstances": []M{{"containerName": "main", "imageDigest": imageDigest}}},
		{"id": "other-namespace", "namespace": namespace + "-other", "clusterId": clusterID},
		{"id": "other-cluster", "namespace": namespace, "clusterId": clusterID + "-other"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/pods":
			// ACS searches unquoted string terms by prefix. Quoted terms match
			// exactly. Model that behavior rather than returning a fixed pod list.
			var matches []M
			for _, pod := range pods {
				matchesQuery := true
				for _, clause := range strings.Split(r.URL.Query().Get("query"), "+") {
					field, term, ok := strings.Cut(clause, ":")
					if !ok {
						t.Error("invalid ACS search clause", clause)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					actual := map[string]string{"Cluster ID": str(pod["clusterId"]), "Namespace": str(pod["namespace"])}[field]
					if exact, err := strconv.Unquote(term); err == nil {
						matchesQuery = matchesQuery && actual == exact
					} else {
						matchesQuery = matchesQuery && strings.HasPrefix(actual, term)
					}
				}
				if matchesQuery {
					matches = append(matches, pod)
				}
			}
			_ = json.NewEncoder(w).Encode(M{"pods": matches})
		case "/v1/deployments/dep1":
			_ = json.NewEncoder(w).Encode(M{
				"name": "api", "namespace": namespace, "clusterId": clusterID,
				"containers": []M{{"name": "main", "image": M{"name": M{"fullName": "registry.acme.test/api:latest"}, "id": imageDigest}}},
			})
		default:
			t.Error("unexpected ACS request", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	s := &Services{C: Config{Env: map[string]string{
		"STACKROX_URL": server.URL, "STACKROX_CLUSTER_ID": clusterID, "STACKROX_TOKEN": "read-token",
	}}, Rox: server.Client()}
	inv, err := s.Inventory(context.Background(), []string{namespace}, false)
	if err != nil {
		t.Fatal("a namespace with the same prefix must not stop the requested inventory:", err)
	}
	if inv.Pods != 1 || len(inv.Images) != 1 || len(inv.Images[0].Targets) != 1 || inv.Images[0].Targets[0].Namespace != namespace {
		t.Fatal("inventory must contain only the requested namespace and cluster", inv)
	}
}
