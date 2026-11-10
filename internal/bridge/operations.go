package bridge

import "context"

func (c Config) OperationsOnly() bool {
	return c.Get("ACCESS_MODE", "operations") == "operations"
}

// Operations uses a single private channel as the audience. Its membership is
// managed in Mattermost; no OpenShift user mapping or API permission is needed.
func (s *Services) operationsAudience(ctx context.Context, owner, ch string, ns []string, scheduled bool) (Audience, error) {
	a := Audience{Policy: "operations"}
	if ch != s.C.Get("MATTERMOST_CHANNEL_ID", "") || !ID.MatchString(ch) {
		return a, problem(403, "Kör kommandot i den konfigurerade privata driftkanalen.")
	}
	a.Namespaces = unique(s.C.Scopes[ch])
	if scheduled {
		a.Namespaces = namespaceIntersection(a.Namespaces, s.C.ScheduleScopes[ch])
	}
	if len(a.Namespaces) == 0 {
		return a, problem(403, "Inga namespaces är konfigurerade för driftkanalen.")
	}
	if len(ns) > 0 {
		if !namespaceSubset(ns, a.Namespaces) {
			return a, problem(403, "Välj ett namespace från SCAN_NAMESPACES.")
		}
		a.Namespaces = unique(ns)
	}
	channel, err := s.MMRequest(ctx, "/api/v4/channels/"+ch, nil)
	if err != nil {
		return a, err
	}
	if str(channel["id"]) != ch || str(channel["type"]) != "P" || num(channel["delete_at"]) != 0 {
		return a, problem(403, "Driftkanalen ska vara privat och aktiv.")
	}
	bot, err := s.Bot(ctx)
	if err != nil {
		return a, err
	}
	users := []string{bot}
	if !scheduled {
		if !ID.MatchString(owner) || owner == bot {
			return a, problem(403, "Kommandot behöver komma från en medlem i driftkanalen.")
		}
		users = append(users, owner)
	}
	for _, id := range users {
		member, err := s.MMRequest(ctx, "/api/v4/channels/"+ch+"/members/"+id, nil)
		if err != nil {
			return a, err
		}
		if str(member["channel_id"]) != ch || str(member["user_id"]) != id {
			return a, problem(403, "Boten och beställaren behöver vara medlemmar i driftkanalen.")
		}
	}
	return a, nil
}
