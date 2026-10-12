package webhook

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/flanksource/canary-checker/api/context"
	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/checks"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/cache"
	"github.com/flanksource/canary-checker/pkg/db"
	"github.com/flanksource/commons/logger"
	dutyApi "github.com/flanksource/duty/api"
	dutyContext "github.com/flanksource/duty/context"
	"github.com/flanksource/duty/models"
	"github.com/flanksource/duty/types"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// Payload is the parsed, size-limited webhook payload. It mirrors
// api.CheckData so transformation templates resolve the same fields; the
// webhook name is delivered out of band to keep the template value identical
// to the legacy one-shot path.
type Payload struct {
	Headers map[string]string `json:"headers"`
	JSON    map[string]any    `json:"json,omitempty"`
	Content string            `json:"content,omitempty"`
}

// pendingRecoveryAge is how old an unconfirmed receipt must be before the
// recovery sweep picks it up, giving the original request room to finish.
const pendingRecoveryAge = 30 * time.Second

// Ingest converges a single (possibly redelivered) webhook delivery.
//
// Identical batches from Alertmanager retries resolve to the same event id.
// Already confirmed events return without side effects; interrupted events
// resume from the checks that were never published, using the canary spec
// generation captured at receive time.
func Ingest(ctx dutyContext.Context, webhookName, authToken string, payload Payload, raw []byte) error {
	if err := EnsureSchema(ctx); err != nil {
		return err
	}

	canaries, err := db.FindCanariesByWebhook(ctx, webhookName)
	if err != nil {
		return err
	} else if len(canaries) == 0 {
		return dutyApi.Errorf(dutyApi.ENOTFOUND, "no canaries found for webhook: %s", webhookName)
	} else if len(canaries) > 1 {
		return dutyApi.Errorf(dutyApi.EINVALID, "%d canaries were found for webhook: %s. please ensure that the webhook name is unique.", len(canaries), webhookName)
	}

	canaryModel := canaries[0]
	if _, err := canaryModel.ToV1(); err != nil {
		return err
	}

	eventID := EventID(webhookName, raw)
	configGeneration := generationHash(canaryModel.Spec)
	presentedTokenHash := hashToken(authToken)

	existing, err := getReceipt(ctx, eventID)
	if err != nil {
		return err
	}

	if existing == nil {
		// First time this event is seen: authorize against the current
		// configuration generation before accepting it.
		currentToken, err := resolveToken(ctx, &canaryModel)
		if err != nil {
			return err
		}
		if currentToken != "" && currentToken != authToken {
			return dutyApi.Errorf(dutyApi.EUNAUTHORIZED, "invalid webhook token")
		}

		existing, err = insertReceipt(ctx, &canaryModel, webhookName, payload, raw, eventID, configGeneration, presentedTokenHash)
		if err != nil {
			return err
		}
	} else {
		// Redelivery: the credential must match either the generation the
		// event was originally accepted with, or the current generation.
		currentToken, tokenErr := resolveToken(ctx, &canaryModel)
		if tokenErr != nil {
			logger.Warnf("webhook event %s: unable to resolve current token, authorizing redelivery against receive-time generation only: %v", eventID, tokenErr)
			currentToken = ""
		}

		if !credentialAccepted(existing, presentedTokenHash, authToken, currentToken) {
			return dutyApi.Errorf(dutyApi.EUNAUTHORIZED, "invalid webhook token")
		}

		if existing.Status == StatusConfirmed {
			// The event already completed: replay must not change committed
			// state, emit extra metrics or create additional status rows.
			return nil
		}

		if existing.ConfigGeneration != configGeneration {
			logger.Infof("webhook event %s: completing with config generation %s captured at receive time (current generation: %s)",
				eventID, existing.ConfigGeneration, configGeneration)
		}
	}

	return process(ctx, existing)
}

// process converts and publishes the event. It is both the first-attempt path
// and the resume/recovery path: every step is keyed by the persisted receipt
// and per-check publication flags.
func process(ctx dutyContext.Context, r *receipt) error {
	canaryV1, payload, err := r.rebuild()
	if err != nil {
		return err
	}
	if canaryV1.Spec.Webhook == nil {
		return dutyApi.Errorf(dutyApi.EINVALID, "webhook configuration missing from the config generation captured for event %s", r.EventID)
	}

	scrapeCtx := context.New(ctx, canaryV1)

	result := pkg.Success(canaryV1.Spec.Webhook, canaryV1)
	result.AddDetails(payload)

	transformed := checks.TransformResults(scrapeCtx, []*pkg.CheckResult{result})

	// No conversion results: nothing to publish. Confirm the event so
	// redelivery stays a no-op, mirroring the legacy empty-loop success.
	if len(transformed) == 0 {
		return markConfirmed(ctx, r.EventID)
	}

	alertTimes := extractAlertTimes(r.RawPayload)
	statusTime := r.ReceivedAt.UTC()

	if err := planChecks(ctx, r, transformed, alertTimes, statusTime); err != nil {
		return err
	}

	var rows []eventCheckRow
	if err := ctx.DB().Where("event_id = ?", r.EventID).Order("ordinal ASC").Find(&rows).Error; err != nil {
		return fmt.Errorf("error loading webhook event checks for %s: %w", r.EventID, err)
	}

	for i := range rows {
		row := &rows[i]
		if row.Ordinal >= len(transformed) {
			return dutyApi.Errorf(dutyApi.EINVALID, "webhook event %s conversion generation changed: planned ordinal %d no longer exists", r.EventID, row.Ordinal)
		}
		cr := transformed[row.Ordinal]
		if row.StatusTime.IsZero() {
			row.StatusTime = statusTime
		}
		cr.StatusTime = row.StatusTime.UTC()

		if !row.Published {
			// cr.Canary is the per-result copy (transform marks resolved
			// checks with a deletion timestamp); use it rather than the
			// shared outer canary.
			skipped, err := publishCheck(ctx, r.EventID, row, cr.Canary, cr)
			if err != nil {
				return err
			}
			if skipped {
				continue
			}
		}

		if !row.MetricsExported && !row.SkippedStale {
			// Downstream replay boundary: metrics are only exported for checks
			// published by (or still unconfirmed in) this attempt, never
			// re-exported once the flag is persisted.
			checks.ExportCheckMetrics(scrapeCtx, pkg.Results{cr}, true)
			if err := ctx.DB().Table(checksTable).
				Where("event_id = ? AND check_key = ?", r.EventID, row.CheckKey).
				Update("metrics_exported", true).Error; err != nil {
				return fmt.Errorf("error marking metrics exported for event %s check %s: %w", r.EventID, row.CheckKey, err)
			}
			row.MetricsExported = true
		}
	}

	return markConfirmed(ctx, r.EventID)
}

// publishCheck publishes a single check within its own transaction, so a
// batch either fully completes or resumes from never-published checks.
func publishCheck(ctx dutyContext.Context, eventID string, row *eventCheckRow, canary v1.Canary, cr *pkg.CheckResult) (bool, error) {
	skipped := false
	txErr := ctx.DB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", row.CheckKey).Error; err != nil {
			return fmt.Errorf("error locking check key %s: %w", row.CheckKey, err)
		}

		// Another instance may have published it while we waited.
		var fresh eventCheckRow
		if err := tx.Where("event_id = ? AND check_key = ?", eventID, row.CheckKey).First(&fresh).Error; err != nil {
			return fmt.Errorf("error reloading event check %s/%s: %w", eventID, row.CheckKey, err)
		}
		if fresh.Published {
			*row = fresh
			skipped = fresh.SkippedStale
			return nil
		}

		// Ordering guard: never let an older event overwrite newer state for
		// the same check. Equality suppresses duplicate notifications (e.g. a
		// re-sent resolved batch), so no extra details are produced and a
		// resolved check cannot be resurrected by a stale firing.
		var watermark sql.NullTime
		if err := tx.Raw(`
			SELECT max(source_event_time)
			FROM webhook_event_checks
			WHERE check_key = ? AND published AND NOT skipped_stale AND event_id <> ?`,
			row.CheckKey, eventID).Scan(&watermark).Error; err != nil {
			return fmt.Errorf("error reading state watermark for %s: %w", row.CheckKey, err)
		}
		if watermark.Valid && !row.SourceEventTime.After(watermark.Time) {
			if err := tx.Model(&eventCheckRow{}).
				Where("event_id = ? AND check_key = ?", eventID, row.CheckKey).
				Updates(map[string]any{"published": true, "skipped_stale": true}).Error; err != nil {
				return fmt.Errorf("error marking stale event check %s/%s: %w", eventID, row.CheckKey, err)
			}
			row.Published = true
			row.SkippedStale = true
			skipped = true
			return nil
		}

		check := pkg.FromV1(canary, cr.Check)
		status := pkg.CheckStatusFromResult(*cr)
		check.Status = lo.Ternary[models.CheckHealthStatus](status.Status, models.CheckStatusHealthy, models.CheckStatusUnhealthy)

		txCtx := ctx.WithDB(tx, ctx.Pool())
		checkIDStr, err := cache.PostgresCache.Add(txCtx, check, status)
		if err != nil {
			return fmt.Errorf("error persisting check %s for event %s: %w", row.CheckKey, eventID, err)
		}

		updates := map[string]any{"published": true, "skipped_stale": false}
		if checkID, parseErr := uuid.Parse(checkIDStr); parseErr == nil && checkID != uuid.Nil {
			updates["check_id"] = checkID
			row.CheckID = &checkID
		}
		if err := tx.Model(&eventCheckRow{}).
			Where("event_id = ? AND check_key = ?", eventID, row.CheckKey).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("error marking event check published %s/%s: %w", eventID, row.CheckKey, err)
		}
		row.Published = true
		return nil
	})
	if txErr != nil {
		// The commit outcome may be uncertain (connection reset etc.).
		// Never assume it locally: the next delivery reconciles by event id
		// and resumes only from unconfirmed checks.
		return false, txErr
	}
	return skipped, nil
}

// EventID is the durable identity of a delivery: a hash over the webhook name
// and the exact raw (size-limited) payload, so retries of the same batch
// converge while distinct batches remain distinct.
func EventID(webhookName string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(webhookName))
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func generationHash(spec types.JSON) string {
	sum := sha256.Sum256(spec)
	return hex.EncodeToString(sum[:])
}

func hashToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// credentialAccepted decides whether a redelivery may resume an event. It
// accepts the credential of the receive-time generation or the current one.
func credentialAccepted(r *receipt, presentedHash, presentedToken, currentToken string) bool {
	if r.AuthTokenHash == "" {
		// The event was accepted while no token was configured.
		return true
	}
	if presentedToken != "" && r.AuthTokenHash == presentedHash {
		return true
	}
	if currentToken != "" && currentToken == presentedToken {
		return true
	}
	return false
}

func resolveToken(ctx dutyContext.Context, canary *pkg.Canary) (string, error) {
	canaryV1, err := canary.ToV1()
	if err != nil {
		return "", err
	}
	webhook := canaryV1.Spec.Webhook
	if webhook == nil || webhook.Token == nil || webhook.Token.IsEmpty() {
		return "", nil
	}
	return ctx.GetEnvValueFromCache(*webhook.Token, canary.Namespace)
}

func getReceipt(ctx dutyContext.Context, eventID string) (*receipt, error) {
	var r receipt
	err := ctx.DB().Where("event_id = ?", eventID).First(&r).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("error fetching webhook event receipt %s: %w", eventID, err)
	}
	return &r, nil
}

// insertReceipt persists the receive-time binding. ON CONFLICT DO NOTHING
// serializes concurrent instances receiving the same redelivery: the loser
// re-reads the winner's receipt and drives the resume path.
func insertReceipt(ctx dutyContext.Context, canary *pkg.Canary, webhookName string, p Payload, raw []byte, eventID, configGeneration, tokenHash string) (*receipt, error) {
	meta := canaryMeta{
		ID:          canary.ID.String(),
		Name:        canary.Name,
		Namespace:   canary.Namespace,
		Labels:      canary.Labels,
		Annotations: canary.Annotations,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}

	if err := ctx.DB().Exec(`
		INSERT INTO webhook_event_receipts
			(event_id, webhook_name, canary_id, raw_payload, headers, spec_snapshot, canary_meta, config_generation, auth_token_hash, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (event_id) DO NOTHING`,
		eventID, webhookName, canary.ID, raw, p.Headers, []byte(canary.Spec), metaJSON,
		configGeneration, tokenHash, StatusReceived).Error; err != nil {
		return nil, fmt.Errorf("error persisting webhook event receipt %s: %w", eventID, err)
	}

	existing, err := getReceipt(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("webhook event receipt %s vanished after insert", eventID)
	}
	return existing, nil
}

func markConfirmed(ctx dutyContext.Context, eventID string) error {
	if err := ctx.DB().Exec(`
		UPDATE webhook_event_receipts
		SET status = ?,
			published_at = COALESCE(published_at, NOW()),
			confirmed_at = COALESCE(confirmed_at, NOW()),
			updated_at = NOW(),
			error = NULL
		WHERE event_id = ?`, StatusConfirmed, eventID).Error; err != nil {
		return fmt.Errorf("error confirming webhook event %s: %w", eventID, err)
	}
	return nil
}

// rebuild reconstructs the canary generation and payload captured when the
// event was first received, so redelivery after config rotation completes
// under the receive-time generation.
func (r *receipt) rebuild() (v1.Canary, Payload, error) {
	var spec v1.CanarySpec
	if err := json.Unmarshal(r.SpecSnapshot, &spec); err != nil {
		return v1.Canary{}, Payload{}, fmt.Errorf("error rebuilding canary spec for event %s: %w", r.EventID, err)
	}

	var meta canaryMeta
	if err := json.Unmarshal(r.CanaryMeta, &meta); err != nil {
		return v1.Canary{}, Payload{}, fmt.Errorf("error rebuilding canary meta for event %s: %w", r.EventID, err)
	}

	var data map[string]any
	if len(r.RawPayload) > 0 {
		if err := json.Unmarshal(r.RawPayload, &data); err != nil {
			return v1.Canary{}, Payload{}, fmt.Errorf("error rebuilding payload for event %s: %w", r.EventID, err)
		}
	}

	canaryID, _ := uuid.Parse(meta.ID)
	canary := v1.Canary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        meta.Name,
			Namespace:   meta.Namespace,
			UID:         k8stypes.UID(canaryID.String()),
			Labels:      meta.Labels,
			Annotations: meta.Annotations,
		},
		Spec: spec,
	}

	payload := Payload{
		Headers: map[string]string(r.Headers),
		JSON:    data,
	}
	if payload.Headers == nil {
		payload.Headers = map[string]string{}
	}
	return canary, payload, nil
}
