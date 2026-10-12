package publication

import (
	"fmt"
	"time"

	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/checks"
	"github.com/google/uuid"
	cron "github.com/robfig/cron/v3"
)

// ShouldGate decides whether a run needs the recoverable publication
// protocol. Runs that cannot produce attachments or HAR keep the historical
// fire-and-forget behavior.
func ShouldGate(canary v1.Canary, harEnabled bool) bool {
	if harEnabled {
		return true
	}
	if checks.DefaultArtifactConnection == "" {
		return false
	}
	for _, check := range canary.Spec.GetAllChecks() {
		if exec, ok := check.(v1.ExecCheck); ok && len(exec.Artifacts) > 0 {
			return true
		}
	}
	return false
}

// ScheduledRunKey returns the deterministic identity of one scheduled tick:
// every replica (and every retry within the same tick) computes the same key,
// so concurrent instances converge onto a single publication row.
func ScheduledRunKey(canaryID uuid.UUID, canary v1.Canary, now time.Time) string {
	slot := scheduledSlot(canary, now)
	return fmt.Sprintf("%s:%s:%d", triggerScheduled, canaryID.String(), slot.Unix())
}

// RunNowRunKey keys a manual run. A client-supplied idempotency key makes a
// retried request resume the same publication; without one each click is its
// own run, matching the historical behavior.
func RunNowRunKey(checkID, idempotencyKey string) string {
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	}
	return fmt.Sprintf("%s:%s:%s", triggerRunNow, checkID, idempotencyKey)
}

// scheduledSlot returns the schedule fire time that is the current slot
// (the most recent fire not after now).
func scheduledSlot(canary v1.Canary, now time.Time) time.Time {
	if canary.Spec.Schedule != "" {
		if sched, err := cron.ParseStandard(canary.Spec.Schedule); err == nil {
			switch s := sched.(type) {
			case cron.ConstantDelaySchedule:
				// @every grids are anchored by robfig/cron at each
				// scheduler's wall clock, so two replicas have different
				// grids. Use epoch-aligned buckets so concurrent ticks
				// within the same interval converge onto the same run key.
				secs := int64(s.Delay.Seconds())
				if secs > 0 {
					return time.Unix(now.Unix()/secs*secs, 0).UTC()
				}
			default:
				if slot, ok := previousFire(sched, now); ok {
					return slot
				}
			}
		}
	}
	if canary.Spec.Interval > 0 {
		secs := int64(canary.Spec.Interval)
		return time.Unix(now.Unix()/secs*secs, 0).UTC()
	}
	return now.Truncate(time.Second)
}

// previousFire walks the cron schedule backwards. It widens the lookup
// window for sparse schedules (daily/monthly) and caps the number of steps
// for dense ones.
func previousFire(sched cron.Schedule, now time.Time) (time.Time, bool) {
	for _, lookback := range []time.Duration{
		2 * time.Hour,
		48 * time.Hour,
		32 * 24 * time.Hour,
		400 * 24 * time.Hour,
	} {
		t := sched.Next(now.Add(-lookback))
		if t.After(now) {
			continue
		}
		for i := 0; i < 100000; i++ {
			next := sched.Next(t)
			if next.After(now) {
				return t, true
			}
			t = next
		}
	}
	return time.Time{}, false
}
