package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Services struct {
	C             Config
	MM, Rox, Kube *http.Client
}

func client(ca string) (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if ca != "" {
		b, e := os.ReadFile(ca)
		if e != nil {
			return nil, fmt.Errorf("CA file unavailable")
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("invalid CA file")
		}
	}
	return &http.Client{Timeout: 190 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func NewServices(c Config) (*Services, error) {
	mm, e := client(c.Get("MATTERMOST_CA_FILE", ""))
	if e != nil {
		return nil, e
	}
	rox, e := client(c.Get("STACKROX_CA_FILE", c.Get("ROX_CA_FILE", "")))
	if e != nil {
		return nil, e
	}
	kube, e := client(c.Get("KUBE_CA_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"))
	if e != nil {
		return nil, e
	}
	return &Services{c, mm, rox, kube}, nil
}
func request(ctx context.Context, client *http.Client, method, address, auth string, payload any) (M, error) {
	var body io.Reader
	if payload != nil {
		b, e := json.Marshal(payload)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, address, body)
	if e != nil {
		return nil, problem(502, "Tjänstens adress kunde inte användas.")
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, problem(502, "Anslutningen till en tjänst misslyckades. Kontrollera driftstatus och certifikat.")
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, (16<<20)+1))
	if e != nil || len(b) > 16<<20 {
		return nil, problem(502, "Tjänstens svar kunde inte läsas inom rapportgränsen.")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, problem(502, fmt.Sprintf("En tjänst nekade förfrågan (HTTP %d).", res.StatusCode))
	}
	var out M
	if json.Unmarshal(b, &out) != nil {
		return nil, problem(502, "En tjänst returnerade ett ogiltigt svar.")
	}
	return out, nil
}
func (s *Services) MMRequest(ctx context.Context, path string, payload any) (M, error) {
	token := s.C.Get("MATTERMOST_BOT_TOKEN", "")
	if token == "" {
		return nil, problem(503, "Botens token saknas.")
	}
	method := "GET"
	if payload != nil {
		method = "POST"
	}
	return request(ctx, s.MM, method, strings.TrimRight(s.C.Get("MATTERMOST_INTERNAL_URL", ""), "/")+path, token, payload)
}
func (s *Services) RoxRequest(ctx context.Context, path, cap string, payload any, scheduled bool) (M, error) {
	k := map[string]string{"read": "STACKROX_TOKEN", "scan": "STACKROX_SCAN_TOKEN", "status": "STACKROX_STATUS_TOKEN"}[cap]
	if scheduled && (cap == "read" || cap == "scan") {
		k = "STACKROX_SCHEDULE_TOKEN"
	}
	tok := s.C.Get(k, "")
	if tok == "" {
		return nil, problem(503, "StackRox-behörigheten för denna åtgärd saknas.")
	}
	method := "GET"
	if payload != nil {
		method = "POST"
	}
	return request(ctx, s.Rox, method, strings.TrimRight(s.C.Get("STACKROX_URL", ""), "/")+path, tok, payload)
}
func (s *Services) Permit(ctx context.Context, user string, groups []string, ns string) (bool, error) {
	b, e := os.ReadFile(s.C.Get("KUBE_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"))
	if e != nil {
		return false, problem(503, "Klustrets kontrollbehörighet saknas.")
	}
	r, e := request(ctx, s.Kube, "POST", strings.TrimRight(s.C.Get("KUBE_API", "https://kubernetes.default.svc"), "/")+"/apis/authorization.k8s.io/v1/subjectaccessreviews", strings.TrimSpace(string(b)), M{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": M{"user": user, "groups": groups, "resourceAttributes": M{"namespace": ns, "verb": "list", "group": "apps", "resource": "deployments"}}})
	if e != nil {
		return false, e
	}
	status := obj(r["status"])
	if str(status["evaluationError"]) != "" {
		return false, problem(503, "Klustret kunde inte verifiera behörigheten.")
	}
	return boolean(status["allowed"]) && !boolean(status["denied"]), nil
}
func (s *Services) Bot(ctx context.Context) (string, error) {
	r, e := s.MMRequest(ctx, "/api/v4/users/me", nil)
	if e != nil {
		return "", e
	}
	id := str(r["id"])
	if !ID.MatchString(id) || id != s.C.Get("MATTERMOST_BOT_USER_ID", "") || !boolean(r["is_bot"]) || has(strings.Fields(str(r["roles"])), "system_admin") {
		return "", problem(503, "Använd en verifierad bot utan administratörsroll.")
	}
	return id, nil
}
func (s *Services) User(ctx context.Context, id string) (string, error) {
	mapped := s.C.Users[id]
	if !ID.MatchString(id) || !validUser(mapped) {
		return "", problem(403, "Ditt Mattermost-konto saknar en administratörsgodkänd koppling till klusterkontot.")
	}
	r, e := s.MMRequest(ctx, "/api/v4/users/"+id, nil)
	if e != nil {
		return "", e
	}
	if str(r["id"]) != id || num(r["delete_at"]) != 0 || boolean(r["is_bot"]) {
		return "", problem(403, "Mattermost-kontot kunde inte verifieras.")
	}
	return mapped, nil
}

type Audience struct {
	Namespaces []string `json:"namespaces"`
	Members    []string `json:"members"`
	Policy     string   `json:"policy"`
}

func (s *Services) Audience(ctx context.Context, ch, actor string, allowed []string) (Audience, error) {
	a := Audience{Namespaces: intersect(allowed, s.C.Scopes[ch]), Policy: s.C.Policies[ch]}
	if a.Policy == "" {
		a.Policy = "common"
	}
	if len(s.C.Scopes[ch]) == 0 {
		return a, problem(403, "Kanalen är inte godkänd för rapporter.")
	}
	channel, e := s.MMRequest(ctx, "/api/v4/channels/"+ch, nil)
	if e != nil {
		return a, e
	}
	if str(channel["id"]) != ch || str(channel["type"]) != "P" || num(channel["delete_at"]) != 0 {
		return a, problem(403, "Rapporter kräver en godkänd privat teamkanal.")
	}
	bot, e := s.Bot(ctx)
	if e != nil {
		return a, e
	}
	// Mattermost members is an array, unlike the other API responses.
	for page := 0; page < 6; page++ {
		members, e := s.members(ctx, ch, page)
		if e != nil {
			return a, e
		}
		for _, m := range members {
			if str(m["channel_id"]) != ch || !ID.MatchString(str(m["user_id"])) {
				return a, problem(502, "Kanalmedlemmarna kunde inte verifieras.")
			}
			a.Members = append(a.Members, str(m["user_id"]))
		}
		if len(members) < 200 {
			break
		}
		if page == 5 {
			return a, problem(413, "Kanalen har för många medlemmar för säker kontroll.")
		}
	}
	a.Members = unique(a.Members)
	if !has(a.Members, actor) || !has(a.Members, bot) {
		return a, problem(403, "Boten och beställaren måste vara medlemmar i kanalen.")
	}
	for _, id := range a.Members {
		if id == bot {
			continue
		}
		u, e := s.User(ctx, id)
		if e != nil {
			return a, e
		}
		if a.Policy == "requester" {
			continue
		}
		var approved []string
		for _, ns := range a.Namespaces {
			ok, e := s.Permit(ctx, u, []string{"system:authenticated"}, ns)
			if e != nil {
				return a, e
			}
			if ok {
				approved = append(approved, ns)
			}
		}
		a.Namespaces = approved
	}
	if len(a.Namespaces) == 0 {
		return a, problem(403, "Inga namespaces är tillåtna för den aktuella kanalen.")
	}
	return a, nil
}
func (s *Services) members(ctx context.Context, ch string, page int) ([]M, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(s.C.Get("MATTERMOST_INTERNAL_URL", ""), "/")+fmt.Sprintf("/api/v4/channels/%s/members?page=%d&per_page=200", ch, page), nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+s.C.Get("MATTERMOST_BOT_TOKEN", ""))
	r, e := s.MM.Do(req)
	if e != nil {
		return nil, problem(502, "Kanalmedlemmarna kunde inte hämtas.")
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	var out []M
	if e != nil || r.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
		return nil, problem(502, "Kanalmedlemmarna kunde inte läsas.")
	}
	return out, nil
}
func (s *Services) ActorAudience(ctx context.Context, owner, ch string, ns []string) (Audience, error) {
	user, e := s.User(ctx, owner)
	if e != nil {
		return Audience{}, e
	}
	var allowed []string
	for _, n := range s.C.Scopes[ch] {
		ok, e := s.Permit(ctx, user, []string{"system:authenticated"}, n)
		if e != nil {
			return Audience{}, e
		}
		if ok {
			allowed = append(allowed, n)
		}
	}
	a, e := s.Audience(ctx, ch, owner, allowed)
	if e != nil {
		return a, e
	}
	if len(ns) > 0 {
		if len(intersect(ns, a.Namespaces)) != len(unique(ns)) {
			return a, problem(403, "Valda namespaces är inte godkända.")
		}
		a.Namespaces = unique(ns)
	}
	return a, nil
}
func (s *Services) ScheduledAudience(ctx context.Context, ch string, ns []string) (Audience, error) {
	user := s.C.Get("SCHEDULE_SERVICE_USER", "")
	parts := strings.Split(user, ":")
	if len(parts) != 4 {
		return Audience{}, problem(503, "Rapporttjänstens konto saknas.")
	}
	var allowed []string
	for _, n := range s.C.ScheduleScopes[ch] {
		ok, e := s.Permit(ctx, user, []string{"system:serviceaccounts", "system:serviceaccounts:" + parts[2], "system:authenticated"}, n)
		if e != nil {
			return Audience{}, e
		}
		if ok && has(s.C.Scopes[ch], n) {
			allowed = append(allowed, n)
		}
	}
	a, e := s.Audience(ctx, ch, s.C.Get("MATTERMOST_BOT_USER_ID", ""), allowed)
	if e != nil {
		return a, e
	}
	if len(ns) > 0 {
		if len(intersect(ns, a.Namespaces)) != len(unique(ns)) {
			return a, problem(403, "Schemat omfattar namespaces som inte längre är tillåtna.")
		}
		a.Namespaces = unique(ns)
	}
	return a, nil
}
func (s *Services) Upload(ctx context.Context, ch string, result M) ([]string, error) {
	b, e := json.MarshalIndent(result, "", "  ")
	if e != nil || len(b) > 8<<20 {
		return nil, problem(413, "Rapportbilagan är för stor.")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	f, e := w.CreateFormFile("files", "acs-scan-report.json")
	if e != nil {
		return nil, e
	}
	if _, e = f.Write(b); e != nil {
		return nil, e
	}
	if e = w.Close(); e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(s.C.Get("MATTERMOST_INTERNAL_URL", ""), "/")+"/api/v4/files?channel_id="+url.QueryEscape(ch), &body)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+s.C.Get("MATTERMOST_BOT_TOKEN", ""))
	r, e := s.MM.Do(req)
	if e != nil {
		return nil, problem(502, "Rapportbilagan kunde inte skickas.")
	}
	defer r.Body.Close()
	data, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var res M
	if e != nil || r.StatusCode < 200 || r.StatusCode >= 300 || json.Unmarshal(data, &res) != nil {
		return nil, problem(502, "Rapportbilagan bekräftades inte.")
	}
	files := arr(res["file_infos"])
	if len(files) != 1 || !ID.MatchString(str(obj(files[0])["id"])) {
		return nil, problem(502, "Rapportbilagans ID saknas.")
	}
	return []string{str(obj(files[0])["id"])}, nil
}
func (s *Services) Post(ctx context.Context, ch string, result M) (string, error) {
	card := ResultMessage(result)
	post := M{"channel_id": ch, "message": card["text"], "props": M{"attachments": card["attachments"]}}
	if _, ok := result["newCves"]; ok {
		obj(post["props"])["cvebridge_new_cves"] = result["newCves"]
		obj(post["props"])["cvebridge_alert_cves"] = result["alertCves"]
	}
	if files := stringsOf(result["reportFileIds"]); len(files) > 0 {
		post["file_ids"] = files
	}
	r, e := s.MMRequest(ctx, "/api/v4/posts", post)
	if e != nil {
		return "", e
	}
	if !ID.MatchString(str(r["id"])) {
		return "", problem(502, "Leveransen kunde inte bekräftas.")
	}
	return str(r["id"]), nil
}
func (s *Services) Notice(ctx context.Context, owner, ch, text string) {
	_, _ = s.MMRequest(ctx, "/api/v4/posts/ephemeral", M{"user_id": owner, "post": M{"channel_id": ch, "message": text}})
}
