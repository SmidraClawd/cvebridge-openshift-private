package bridge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const sensorCheckInterval = 5 * time.Minute
const sensorContactLimit = 10 * time.Minute

// A Central API failure is unknown, never evidence that Sensor disconnected.
// Only the configured cluster is read; no direct Sensor or Kubernetes access
// and no certificate inventory are needed.
func (s *Services) sensorStatusAt(ctx context.Context, now time.Time) M {
	id := s.C.Get("STACKROX_CLUSTER_ID", "")
	r := M{"kind": "sensor_status", "state": "unknown", "clusterId": id,
		"checkedAt": now.UTC().Format(time.RFC3339), "lastContact": ""}
	reply, err := s.RoxRequest(ctx, "/v1/clusters/"+url.PathEscape(id), "read", nil, false)
	if err != nil {
		r["reason"] = message(err)
		return r
	}
	cluster := obj(reply["cluster"])
	if id == "" || str(cluster["id"]) != id {
		r["reason"] = "ACS returnerade inte det konfigurerade klustret. Kontrollera kluster-ID och tokenens access scope."
		return r
	}
	r["clusterName"] = str(cluster["name"])
	// Older ACS versions expose status.lastContact. A present but invalid new
	// field must not be replaced by an older timestamp and reported as healthy.
	stamp := str(obj(cluster["healthStatus"])["lastContact"])
	if stamp == "" {
		stamp = str(obj(cluster["status"])["lastContact"])
	}
	point, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || point.IsZero() {
		r["reason"] = "ACS saknar en giltig tid för senaste sensorkontakt. Kontrollera valt kluster i ACS System Health."
		return r
	}
	age := now.Sub(point)
	if age < -time.Minute {
		r["reason"] = "Sensorns kontakttid ligger i framtiden. Kontrollera klockorna."
		return r
	}
	if age < 0 {
		age = 0
	}
	r["lastContact"] = point.UTC().Format(time.RFC3339)
	r["ageMinutes"] = age.Minutes()
	r["state"] = "connected"
	if age > sensorContactLimit {
		r["state"] = "missing"
	}
	return r
}

func (s *Services) sensorMonitorEnabled() bool {
	return s.C.Flag("SENSOR_MONITOR_ENABLED", false) && s.C.Get("DATABASE_MONITOR_CHANNEL_ID", "") != ""
}

func (s *Services) logSensorMonitorStartup() {
	enabled := s.sensorMonitorEnabled()
	fields := M{"enabled": enabled, "cluster_id": s.C.Get("STACKROX_CLUSTER_ID", ""),
		"check_interval_minutes": int(sensorCheckInterval / time.Minute),
		"contact_limit_minutes":  int(sensorContactLimit / time.Minute), "next_check": "immediate"}
	if !enabled {
		fields["next_check"] = "disabled"
		fields["reason"] = "sensor_monitor_disabled_or_missing_monitor_channel"
		fields["hint"] = "SENSOR_MONITOR_ENABLED=true använder DATABASE_MONITOR_CHANNEL_ID och STACKROX_CLUSTER_ID."
	}
	s.acsInfo("sensor_monitor_startup", fields)
}

// This worker is independent of both database checks and long image scans.
func (a *App) startSensorMonitor(now time.Time) {
	if !a.S.sensorMonitorEnabled() || a.ctx.Err() != nil || !a.sensor.TryLock() {
		return
	}
	if now.Before(a.sensorNext) {
		a.sensor.Unlock()
		return
	}
	a.sensorNext = now.Add(sensorCheckInterval)
	a.tasks.Add(1)
	go func() {
		defer a.tasks.Done()
		defer a.sensor.Unlock()
		ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
		defer cancel()
		if err := a.checkSensorMonitor(ctx, now); err != nil {
			a.S.acsInfo("sensor_monitor_retry_scheduled", M{"retry_after_minutes": 5})
		}
	}()
}

func (a *App) checkSensorMonitor(ctx context.Context, now time.Time) (err error) {
	if !a.S.sensorMonitorEnabled() {
		return nil
	}
	ch := a.S.C.Get("DATABASE_MONITOR_CHANNEL_ID", "")
	stage := "state_read"
	defer func() {
		if err != nil {
			reason := "state_unavailable"
			if stage != "state_read" && stage != "state_write" {
				reason = message(err)
			}
			a.S.acsInfo("sensor_monitor_check_failed", M{"stage": stage, "reason": reason})
		}
	}()
	identity := []string{strings.TrimRight(a.S.C.Get("STACKROX_URL", ""), "/"), a.S.C.Get("STACKROX_CLUSTER_ID", ""), ch}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(encode(identity))))
	var previous string
	var notified int64
	err = a.Store.DB.QueryRowContext(ctx, `SELECT state,notified_at FROM sensor_monitor WHERE monitor_key=?`, key).Scan(&previous, &notified)
	initial := errors.Is(err, sql.ErrNoRows)
	if err != nil && !initial {
		return err
	}
	err = nil
	if !initial && (notified <= 0 || (previous != "connected" && previous != "missing" && previous != "unknown")) {
		return problem(503, "Sensorbevakningens sparade status är ogiltig.")
	}
	a.S.acsInfo("sensor_monitor_check_start", M{"cluster_id": identity[1]})
	// Keep enough of the parent deadline for the Mattermost warning on timeout.
	probe, cancel := context.WithTimeout(ctx, 75*time.Second)
	result := a.S.sensorStatusAt(probe, now)
	cancel()
	state := str(result["state"])
	a.S.acsInfo("sensor_monitor_acs_complete", M{"state": state, "reason": str(result["reason"]), "last_contact": str(result["lastContact"])})
	last := time.Unix(notified, 0)
	if !initial && state == previous && !now.Before(last) && now.Sub(last) < databaseReportInterval {
		a.S.acsInfo("sensor_monitor_post_skipped", M{"state": state, "reason": "unchanged_within_24_hours"})
		return nil
	}
	stage = "mattermost_destination"
	if err = a.S.databaseMonitorDestination(ctx, ch); err != nil {
		return err
	}
	result["kind"] = "sensor_monitor"
	result["recovered"] = !initial && previous == "missing" && state == "connected"
	result["verifiedAgain"] = !initial && previous == "unknown" && state == "connected"
	stage = "mattermost_post"
	if _, err = a.S.Post(ctx, ch, result); err != nil {
		return err
	}
	a.S.acsInfo("sensor_monitor_post_sent", M{"state": state})
	stage = "state_write"
	// As with database monitoring, a process crash after a confirmed post but
	// before this commit can cause a duplicate. Failed posts never advance state.
	_, err = a.Store.DB.ExecContext(ctx, `INSERT INTO sensor_monitor (monitor_key,state,notified_at) VALUES (?,?,?) ON CONFLICT(monitor_key) DO UPDATE SET state=excluded.state,notified_at=excluded.notified_at`, key, state, now.Unix())
	if err == nil {
		a.S.acsInfo("sensor_monitor_check_complete", M{"state": state, "next_check_after_minutes": 5})
	}
	return err
}

func sensorMonitorMessage(r M) M {
	title, color := "Sensorkontakten kan inte verifieras", "#D97732"
	action := "Kontrollera anslutningen till ACS Central, kluster-ID och ACS-tokenens Cluster: Read samt access scope."
	switch str(r["state"]) {
	case "connected":
		title, color = "Sensor har nylig kontakt med ACS Central", "#329C89"
		if boolean(r["recovered"]) {
			title = "Sensor · Kontakt återställd"
		} else if boolean(r["verifiedAgain"]) {
			title = "Sensorkontakten kan verifieras igen"
		}
		action = "Ingen åtgärd behövs för sensorkontaktens ålder."
	case "missing":
		title, color = "Sensor · Kontakt saknas inom tidsgränsen", "#D64550"
		action = "Kontrollera Sensor-poden i det angivna klustret och dess nätverk till ACS Central. ACS kan sakna aktuell klusterinformation."
	}
	cluster := str(r["clusterName"])
	if cluster == "" {
		cluster = str(r["clusterId"])
	}
	text := "**Kluster:** " + inert(cluster, 100) + "\n**Kluster-ID:** " + inert(str(r["clusterId"]), 100)
	if stamp := str(r["lastContact"]); stamp != "" {
		text += fmt.Sprintf("\n**Senaste kontakt:** %s\n**Ålder:** %.1f minuter · gräns 10 minuter", inert(stamp, 40), num(r["ageMinutes"]))
	}
	if reason := str(r["reason"]); reason != "" {
		text += "\n**Orsak:** " + inert(reason, 200)
	}
	text += "\n**Kontrollerad:** " + inert(str(r["checkedAt"]), 40) + "\n\n**Åtgärd:** " + action
	if str(r["kind"]) == "sensor_monitor" {
		text += "\nKontroll var femte minut · status var 24:e timme samt vid ändrat läge."
	}
	return card(title, text, "**ACS · Driftbevakning av sensorkontakt**", color)
}
