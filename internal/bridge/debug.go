package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Debugging is enabled for the private operations bot. Monitor lifecycle logs
// remain visible at info level. Credentials, bodies and URL queries are omitted.
func (s *Services) acsDebugEnabled() bool {
	return strings.EqualFold(s.C.Get("LOG_LEVEL", "debug"), "debug")
}

func (s *Services) acsDebug(event string, fields M) {
	if !s.acsDebugEnabled() {
		return
	}
	s.acsLog("DEBUG", event, fields)
}

func (s *Services) acsInfo(event string, fields M) {
	s.acsLog("INFO", event, fields)
}

func (s *Services) logMonitorStartup() {
	enabled := s.C.Get("DATABASE_MONITOR_CHANNEL_ID", "") != ""
	fields := M{
		"enabled": enabled, "debug_enabled": s.acsDebugEnabled(),
		"component":               s.C.Get("STACKROX_SCANNER_COMPONENT", "SCANNER"),
		"acs_configured":          s.C.Get("STACKROX_URL", "") != "",
		"status_token_configured": s.C.Get("STACKROX_STATUS_TOKEN", "") != "",
		"check_interval_minutes":  int(databaseCheckInterval / time.Minute),
		"next_check":              "immediate",
	}
	if !enabled {
		fields["next_check"] = "disabled"
		fields["reason"] = "missing_monitor_channel"
		fields["hint"] = "Ange DATABASE_MONITOR_CHANNEL_ID i ConfigMap. Använd driftkanalens Mattermost-ID."
	}
	s.acsInfo("monitor_startup", fields)
}

func (s *Services) acsLog(level, event string, fields M) {
	redact := func(value string) string {
		for key, secret := range s.C.Env {
			key = strings.ToUpper(key)
			if secret != "" && (strings.Contains(key, "TOKEN") || strings.Contains(key, "PASSWORD") || strings.Contains(key, "SECRET") || strings.Contains(key, "API_KEY")) {
				for _, form := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
					value = strings.ReplaceAll(value, form, "[REDACTED]")
				}
			}
		}
		if len(value) > 1024 {
			value = value[:1024] + "..."
		}
		return value
	}
	entry := M{"event": event}
	for key, value := range fields {
		switch value := value.(type) {
		case string:
			entry[key] = redact(value)
		case []string:
			items := make([]string, len(value))
			for i, item := range value {
				items[i] = redact(item)
			}
			entry[key] = items
		case bool, int, int64:
			entry[key] = value
		}
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	logger := s.debugLogger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("[ACS %s] %s", level, encoded)
}

func acsEndpoint(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		return "invalid_url"
	}
	// Deliberately omit userinfo and every query value.
	return u.Scheme + "://" + u.Host + u.Path
}

type acsTransport struct {
	base                http.RoundTripper
	status              int
	contentType, server string
	errorKind           string
}

func (t *acsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if response != nil {
		t.status = response.StatusCode
		t.contentType = response.Header.Get("Content-Type")
		t.server = response.Header.Get("Server")
		if t.status < 200 || t.status >= 300 {
			t.errorKind = "http"
		}
	}
	if err != nil {
		t.errorKind = acsNetworkError(err)
	}
	return response, err
}

func acsNetworkError(err error) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var dns *net.DNSError
	var network net.Error
	var record tls.RecordHeaderError
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &unknown):
		return "tls_unknown_authority"
	case errors.As(err, &hostname):
		return "tls_hostname_mismatch"
	case errors.As(err, &invalid):
		return "tls_certificate_invalid"
	case errors.As(err, &record):
		return "tls_handshake"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &network) && network.Timeout():
		return "timeout"
	default:
		return "connection"
	}
}

func acsHTTPHint(status int, path string) string {
	switch {
	case status == 401:
		return "Kontrollera ACS-tokenens giltighet och att den hör till rätt Central."
	case status == 403 && strings.HasPrefix(path, "/v1/integrationhealth/vulndefinitions"):
		return "Kontrollera Administration: Read på ACS-tokenens roll, samt eventuell proxy framför ACS."
	case status == 403 && strings.HasPrefix(path, "/v1/images/scan"):
		return "Kontrollera Image: Write och tokenens access scope, samt eventuell proxy framför ACS."
	case status == 403 && strings.HasPrefix(path, "/v1/clusters/"):
		return "Kontrollera Cluster: Read och att ACS-tokenens access scope omfattar valt kluster."
	case status == 403:
		return "Kontrollera ACS-tokenens läsrättigheter och access scope, samt eventuell proxy framför ACS."
	case status == 404:
		return "Kontrollera Central-adressen, API-sökvägen och ACS-versionen."
	case status >= 300 && status < 400:
		return "ACS-adressen omdirigerar. Kontrollera Central-adressen och eventuell inloggningsproxy."
	case status == 0:
		return "Kontrollera error_kind, Central-adressen, DNS, nätverk och CA-paketet."
	default:
		return "Kontrollera HTTP-kod, svarstyp och driftstatus i ACS Central."
	}
}
