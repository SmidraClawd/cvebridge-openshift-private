package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"sigs.k8s.io/yaml"
)

var applicationManifests = map[string]string{
	"ServiceAccount": "serviceaccounts.yaml", "Secret": "secret.yaml",
	"ConfigMap": "configmap.yaml", "PersistentVolumeClaim": "pvc.yaml",
	"Deployment": "deployment.yaml", "Service": "service.yaml", "Route": "route.yaml",
}

// RenderManifests writes reviewable YAML. Cluster-wide bootstrap is separate
// from the namespace resources so applying app/ never requires cluster admin.
func RenderManifests(directory string, values map[string]string) error {
	files := map[string][]byte{}
	for _, part := range []string{"bootstrap", "deployment"} {
		var rendered bytes.Buffer
		if err := Render(&rendered, values, part); err != nil {
			return err
		}
		var list struct {
			Items []M `json:"items"`
		}
		if err := json.Unmarshal(rendered.Bytes(), &list); err != nil {
			return err
		}
		for _, item := range list.Items {
			name := "bootstrap.yaml"
			if part == "deployment" {
				base, ok := applicationManifests[str(item["kind"])]
				if !ok {
					return fmt.Errorf("unsupported application resource kind")
				}
				name = filepath.Join("app", base)
			}
			data, err := yaml.Marshal(item)
			if err != nil {
				return err
			}
			if len(files[name]) != 0 {
				files[name] = append(files[name], []byte("---\n")...)
			}
			files[name] = append(files[name], data...)
		}
	}
	// Validate every resource before changing any previous generated files.
	for _, dir := range []string{directory, filepath.Join(directory, "app")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(directory, name)
		if err := writeManifest(path, files[name]); err != nil {
			return err
		}
	}
	// Only clean our own optional outputs, never arbitrary files in app/.
	for _, name := range applicationManifests {
		relative := filepath.Join("app", name)
		if _, exists := files[relative]; !exists {
			if err := os.Remove(filepath.Join(directory, relative)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func writeManifest(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cvebridge-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err = temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
