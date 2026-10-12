package webhook

import (
	"encoding/json"
	"fmt"
	"time"

	dutyContext "github.com/flanksource/duty/context"
	"github.com/flanksource/duty/types"

	"github.com/flanksource/canary-checker/pkg"
)

func errAndWrap(msg, eventID, checkKey string, err error) error {
	if checkKey == "" {
		return fmt.Errorf("%s for event %s: %w", msg, eventID, err)
	}
	return fmt.Errorf("%s %s for event %s: %w", msg, checkKey, eventID, err)
}

type alertSource struct {
	at       time.Time
	resolved bool
}

// planChecks persists the converted check set bound to the receipt. Existing
// rows (from an interrupted attempt) are preserved so publication resumes
// exactly where it stopped.
func planChecks(ctx dutyContext.Context, r *receipt, transformed []*pkg.CheckResult, alertTimes []alertSource, statusTime time.Time) error {
	planned := make([]plannedCheck, 0, len(transformed))

	for i, cr := range transformed {
		checkType := cr.Check.GetType()
		checkName := cr.Check.GetName()
		key := r.CanaryID.String() + "|" + checkType + "|" + checkName

		at := statusTime
		resolved := false

		if i == 0 {
			// The parent webhook check carries no per-alert event time.
			at = statusTime
		} else if i-1 < len(alertTimes) {
			src := alertTimes[i-1]
			if !src.at.IsZero() {
				at = src.at
			}
			resolved = src.resolved
		}

		// The transformation marks the check's canary copy with a deletion
		// timestamp when the template emits deletedAt (e.g. resolved alerts).
		if !cr.Canary.DeletionTimestamp.IsZero() {
			resolved = true
			if i-1 >= 0 && i-1 < len(alertTimes) && alertTimes[i-1].at.IsZero() {
				at = cr.Canary.DeletionTimestamp.Time.UTC()
			}
		}

		row := eventCheckRow{
			EventID:         r.EventID,
			Ordinal:         i,
			CheckKey:        key,
			SourceEventTime: at.UTC(),
			StatusTime:      statusTime,
			Resolved:        resolved,
		}
		if err := ctx.DB().Exec(`
			INSERT INTO webhook_event_checks
				(event_id, ordinal, check_key, source_event_time, status_time, resolved)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (event_id, check_key) DO NOTHING`,
			row.EventID, row.Ordinal, row.CheckKey, row.SourceEventTime, row.StatusTime, row.Resolved).Error; err != nil {
			return errAndWrap("error planning webhook event check", r.EventID, key, err)
		}

		planned = append(planned, plannedCheck{
			Ordinal:         i,
			CheckKey:        key,
			Type:            checkType,
			Name:            checkName,
			SourceEventTime: row.SourceEventTime,
			StatusTime:      row.StatusTime,
			Resolved:        resolved,
		})
	}

	checksJSON, err := json.Marshal(planned)
	if err != nil {
		return err
	}

	// Keep the first conversion snapshot: replans on redelivery describe the
	// same event because the receive-time spec generation is reused.
	if err := ctx.DB().Exec(`
		UPDATE webhook_event_receipts
		SET checks = ?, updated_at = NOW()
		WHERE event_id = ? AND checks = '[]'`, types.JSON(checksJSON), r.EventID).Error; err != nil {
		return errAndWrap("error persisting converted check set", r.EventID, "", err)
	}

	return nil
}

// extractAlertTimes reads the source event time (Alertmanager startsAt /
// endsAt) of each alert in the raw payload. Transformation templates emit one
// check per alert, preserving order, so converted child checks map back by
// index. Non-Alertmanager payloads simply yield no times.
func extractAlertTimes(raw types.JSON) []alertSource {
	var envelope struct {
		Alerts []struct {
			Status   string `json:"status"`
			StartsAt string `json:"startsAt"`
			EndsAt   string `json:"endsAt"`
		} `json:"alerts"`
	}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil
	}

	out := make([]alertSource, 0, len(envelope.Alerts))
	for _, a := range envelope.Alerts {
		src := alertSource{resolved: a.Status == "resolved"}
		if end := parseEventTime(a.EndsAt); end != nil {
			src.at = *end
			src.resolved = true
		} else if start := parseEventTime(a.StartsAt); start != nil {
			src.at = *start
		}
		out = append(out, src)
	}
	return out
}

func parseEventTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}
