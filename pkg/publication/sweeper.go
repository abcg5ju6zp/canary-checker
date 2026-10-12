package publication

import (
	"fmt"
	"strconv"

	"github.com/flanksource/commons/logger"
	dutycontext "github.com/flanksource/duty/context"
	dutyjob "github.com/flanksource/duty/job"
	"gorm.io/gorm"
)

// RecoverCheckRunPublications resumes publications interrupted by a crash, a
// lost response or an unavailable database/object store. It only ever
// advances unconfirmed steps: external checks are not re-executed, statuses
// and artifact rows are not duplicated, and metrics/HAR/kubernetes outputs
// are replayed individually via their compare-and-set columns.
var RecoverCheckRunPublications = &dutyjob.Job{
	Name:       "RecoverCheckRunPublications",
	Schedule:   "@every 1m",
	RunNow:     true,
	Singleton:  true,
	JobHistory: true,
	Retention:  dutyjob.RetentionFew,
	Fn: func(rt dutyjob.JobRuntime) error {
		return Sweep(rt.Context)
	},
}

// Sweep claims and drives every stale, unfinalized publication.
func Sweep(ctx dutycontext.Context) error {
	if err := EnsureSchema(ctx); err != nil {
		return err
	}

	var rows []CheckRunPublication
	if err := ctx.DB().
		Where("status IN ?", []string{statusExecuting, statusStaged, statusCommitted}).
		Where("finalized_at IS NULL").
		Where("lease_until IS NULL OR lease_until <= NOW()").
		Order("created_at ASC").
		Limit(100).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("error listing recoverable publications: %w", err)
	}

	var sweepErr error
	for i := range rows {
		if err := recoverRow(ctx, &rows[i]); err != nil {
			logger.Errorf("error recovering publication %s: %v", rows[i].RunKey, err)
			if sweepErr == nil {
				sweepErr = err
			}
		}
	}
	return sweepErr
}

func recoverRow(ctx dutycontext.Context, row *CheckRunPublication) error {
	// Take over the stale lease first.
	res := ctx.DB().Model(&CheckRunPublication{}).
		Where("id = ? AND (lease_until IS NULL OR lease_until <= NOW())", row.ID).
		Updates(map[string]any{
			"owner":       ownerID(),
			"lease_until": gorm.Expr("NOW() + (? || ' seconds')::interval", strconv.Itoa(int(leaseDuration.Seconds()))),
			"attempts":    gorm.Expr("attempts + 1"),
			"updated_at":  gorm.Expr("NOW()"),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return nil
	}

	if row.Status == statusExecuting && len(row.Snapshot) == 0 {
		// The checks never finished capturing: their external effects
		// cannot be proven complete, so this round must not take effect.
		// The next scheduled tick runs as a new publication.
		return ctx.DB().Model(&CheckRunPublication{}).
			Where("id = ?", row.ID).
			Updates(map[string]any{
				"status":       statusAborted,
				"abort_reason": "owner died before the run was staged",
				"finalized_at": gorm.Expr("NOW()"),
				"updated_at":   gorm.Expr("NOW()"),
			}).Error
	}

	p := &Publication{ctx: ctx, row: row, live: false}
	_, err := p.resume()
	return err
}
