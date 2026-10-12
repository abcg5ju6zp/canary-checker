package webhook

import (
	"fmt"
	"time"

	"github.com/flanksource/commons/logger"
	dutyContext "github.com/flanksource/duty/context"
	dutyjob "github.com/flanksource/duty/job"
)

// RecoveryJob resumes deliveries left unconfirmed by a crash or a lost HTTP
// connection, completing them with the config generation captured at receive
// time (stored in the receipt).
var RecoveryJob = &dutyjob.Job{
	Name:       "WebhookEventRecovery",
	Schedule:   "@every 1m",
	Singleton:  true,
	JobHistory: true,
	Retention:  dutyjob.RetentionFew,
	Fn: func(rt dutyjob.JobRuntime) error {
		return RecoverPending(rt.Context, 100)
	},
}

// RecoverPending drives all stale unconfirmed receipts to completion.
func RecoverPending(ctx dutyContext.Context, limit int) error {
	if err := EnsureSchema(ctx); err != nil {
		return err
	}

	cutoff := time.Now().Add(-pendingRecoveryAge)
	var receipts []receipt
	if err := ctx.DB().
		Where("status IN ?", []string{StatusReceived, StatusPublished}).
		Where("received_at < ?", cutoff).
		Order("received_at ASC").
		Limit(limit).
		Find(&receipts).Error; err != nil {
		return fmt.Errorf("error listing pending webhook event receipts: %w", err)
	}

	failures := 0
	for i := range receipts {
		r := receipts[i]
		if err := process(ctx, &r); err != nil {
			failures++
			logger.Errorf("webhook event %s recovery failed: %v", r.EventID, err)
			_ = ctx.DB().Exec(`
				UPDATE webhook_event_receipts SET error = ?, updated_at = NOW()
				WHERE event_id = ?`, err.Error(), r.EventID).Error
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d pending webhook events failed to recover", failures, len(receipts))
	}
	return nil
}
