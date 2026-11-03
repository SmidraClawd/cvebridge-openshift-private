package bridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func caTestServer(t *testing.T, name string) (*httptest.Server, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return server, path
}

func TestServicesTrustOnlyConfiguredCAs(t *testing.T) {
	mm, mmCA := caTestServer(t, "Mattermost CA")
	rox, roxCA := caTestServer(t, "ACS CA")
	kube, kubeCA := caTestServer(t, "Kubernetes CA")
	// A CA made available as host trust must not broaden another client's trust.
	t.Setenv("SSL_CERT_FILE", mmCA)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	env := testEnv()
	env["MATTERMOST_CA_FILE"], env["STACKROX_CA_FILE"], env["KUBE_CA_FILE"] = mmCA, roxCA, kubeCA
	config, err := NewConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(config)
	if err != nil {
		t.Fatal(err)
	}
	servers := []*httptest.Server{mm, rox, kube}
	for i, service := range []*http.Client{services.MM, services.Rox, services.Kube} {
		t.Cleanup(service.CloseIdleConnections)
		for j, server := range servers {
			response, err := service.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if i == j {
				if err != nil || response.StatusCode != http.StatusOK {
					t.Fatalf("service %d rejected its configured CA: %v", i, err)
				}
			} else {
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Fatalf("service %d must reject service %d's unrelated CA: %v", i, j, err)
				}
			}
		}
	}
	transport := services.MM.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "wrong.invalid"
	wrongHost := &http.Client{Transport: transport}
	t.Cleanup(wrongHost.CloseIdleConnections)
	response, err := wrongHost.Get(mm.URL)
	if response != nil {
		response.Body.Close()
	}
	var hostname x509.HostnameError
	if !errors.As(err, &hostname) {
		t.Fatalf("configured CA must not disable hostname verification: %v", err)
	}
	noCA, err := client("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(noCA.CloseIdleConnections)
	response, err = noCA.Get(mm.URL)
	if response != nil {
		response.Body.Close()
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("missing CA must not fall back to host trust: %v", err)
	}
}

func TestTLSClientRejectsUnavailableOrInvalidCA(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string]string{"empty": "", "invalid": "not a PEM certificate"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := client(path); err == nil {
			t.Fatalf("accepted %s CA file", name)
		}
	}
	if _, err := client(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted a missing CA file")
	}
}
