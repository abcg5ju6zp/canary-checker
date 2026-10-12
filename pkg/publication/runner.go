package publication

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	artifactslib "github.com/flanksource/artifacts"
	canarycontext "github.com/flanksource/canary-checker/api/context"
	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/checks"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/runner"
	"github.com/flanksource/commons/logger"
	dutycontext "github.com/flanksource/duty/context"
	"github.com/flanksource/duty/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	// TriggerScheduled marks publications started by the cron scheduler.
	TriggerScheduled = triggerScheduled
	// TriggerRunNow marks publications started by the Run Now API.
	TriggerRunNow = triggerRunNow

	leaseDuration  = 15 * time.Minute
	heartbeatEvery = 5 * time.Minute
)

// Outcome is the result of driving a run through its publication.
type Outcome struct {
	Results []*pkg.CheckResult
	// Skipped is true when another live owner is processing the same run
	// key: no checks were executed and nothing was published by this caller.
	Skipped bool
	// Reused is true when the publication already existed (finalized or
	// recovered): no external checks were executed by this caller and
	// post-run transformed-check reconciliation must not run again.
	Reused bool
	// TransformedChecksCreated / CheckIDDeleteStrategyMap are populated only
	// when this caller performed the live commit.
	TransformedChecksCreated []string
	CheckIDDeleteStrategyMap map[string]string
	// SecretLookupRateLimitSkipped is populated only for live executions.
	SecretLookupRateLimitSkipped int
}

// Publication is the in-process driver and hook implementation for one bound
// run publication.
type Publication struct {
	ctx    dutycontext.Context
	row    *CheckRunPublication
	canary v1.Canary

	// live execution state
	live        bool
	results     pkg.Results
	manifests   []ArtifactManifest
	harData     []byte
	harFilename string
	metrics     []pkg.Metric

	stopHeartbeat chan struct{}
	stopped       sync.Once
}

func ownerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s/%s/%d", runner.RunnerName, host, os.Getpid())
}

// RunGated binds one check run (scheduled tick or Run Now) to a recoverable
// publication. runKey identifies the same logical run across replicas,
// retries and restarts; every driver of the same key converges onto the
// single row.
func RunGated(ctx dutycontext.Context, dbCanary pkg.Canary, canary v1.Canary, runKey, trigger string) (*Outcome, error) {
	if err := EnsureSchema(ctx); err != nil {
		return nil, fmt.Errorf("error ensuring publication schema: %w", err)
	}

	now := time.Now().UTC()
	runTime := now.Truncate(time.Second)
	canaryID := dbCanary.ID
	row := &CheckRunPublication{
		ID:         uuid.New(),
		RunKey:     runKey,
		CanaryID:   &canaryID,
		Source:     canary.Annotations["source"],
		Trigger:    trigger,
		Status:     statusExecuting,
		RunTime:    runTime,
		Owner:      ownerID(),
		LeaseUntil: ptrTime(now.Add(leaseDuration)),
		Attempts:   1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := ctx.DB().Create(row).Error; err != nil {
		if !isUniqueViolation(err) {
			return nil, fmt.Errorf("error creating publication: %w", err)
		}
		existing, err := loadPublication(ctx, runKey)
		if err != nil {
			return nil, fmt.Errorf("error loading existing publication: %w", err)
		}
		return adopt(ctx, existing, canary)
	}

	p := &Publication{ctx: ctx, row: row, canary: canary, live: true}
	return p.execute()
}

// adopt decides what this driver does with a publication row created by
// another attempt: skip while another owner is live, recover finished
// publications, or take over stale ones.
func adopt(ctx dutycontext.Context, row *CheckRunPublication, canary v1.Canary) (*Outcome, error) {
	switch row.Status {
	case statusAborted:
		return nil, fmt.Errorf("publication %s was aborted: %s", row.RunKey, row.AbortReason)
	case statusSucceeded:
		out := &Outcome{Reused: true}
		if len(row.Snapshot) > 0 {
			if results, err := decodeSnapshotResults(row.Snapshot, row.RunTime); err == nil {
				out.Results = results
			} else {
				logger.Errorf("error decoding finalized publication %s: %v", row.RunKey, err)
			}
		}
		return out, nil
	}

	if row.LeaseUntil != nil && row.LeaseUntil.After(time.Now()) && row.Owner != ownerID() {
		// Another instance is actively driving the same run.
		return &Outcome{Skipped: true}, nil
	}

	// Take over the lease. The predicate makes the claim single-winner when
	// multiple replicas race to recover the same row.
	res := ctx.DB().Model(&CheckRunPublication{}).
		Where("id = ? AND (lease_until IS NULL OR lease_until <= NOW())", row.ID).
		Updates(map[string]any{
			"owner":       ownerID(),
			"lease_until": gorm.Expr("NOW() + (? || ' seconds')::interval", strconv.Itoa(int(leaseDuration.Seconds()))),
			"attempts":    gorm.Expr("attempts + 1"),
			"updated_at":  gorm.Expr("NOW()"),
		})
	if res.Error != nil {
		return nil, fmt.Errorf("error claiming publication: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return &Outcome{Skipped: true}, nil
	}

	row.Owner = ownerID()
	t := time.Now().Add(leaseDuration)
	row.LeaseUntil = &t

	if row.Status == statusExecuting && len(row.Snapshot) == 0 {
		// The previous owner died before the checks could be captured. The
		// external probes cannot be proven complete, so start them over
		// under the same publication identity; object keys are derived from
		// the stable run time and are overwritten/re-verified.
		if err := resetForExecution(ctx, row.ID); err != nil {
			return nil, err
		}
		p := &Publication{ctx: ctx, row: row, canary: canary, live: true}
		return p.execute()
	}

	p := &Publication{ctx: ctx, row: row, canary: canary, live: false}
	return p.resume()
}

func resetForExecution(ctx dutycontext.Context, id uuid.UUID) error {
	return ctx.DB().Model(&CheckRunPublication{}).Where("id = ?", id).
		Updates(map[string]any{
			"status":               statusExecuting,
			"snapshot":             nil,
			"artifacts":            nil,
			"har_data":             nil,
			"har_filename":         nil,
			"har_path":             nil,
			"har_checksum":         nil,
			"har_size":             0,
			"k8s_payload":          nil,
			"abort_reason":         nil,
			"updated_at":           gorm.Expr("NOW()"),
			"results_committed_at": nil,
		}).Error
}

// execute runs the external checks, stages and verifies their artifacts, and
// then drives the commit/output state machine.
func (p *Publication) execute() (*Outcome, error) {
	p.startHeartbeat()
	defer p.stopHeartbeatNow()

	canaryCtx := canarycontext.New(p.ctx, p.canary)
	canaryCtx.Publication = p

	results, meta, err := checks.RunChecks(canaryCtx)
	if err != nil {
		_ = p.abort(fmt.Sprintf("check execution failed: %s", err.Error()))
		return nil, fmt.Errorf("error running checks for publication %s: %w", p.row.RunKey, err)
	}
	if results == nil {
		// Deleted canary short-circuit: nothing to publish.
		_ = p.abort("canary deleted before run completed")
		return &Outcome{Results: nil}, nil
	}
	p.results = results

	if err := p.persistStage(); err != nil {
		return nil, fmt.Errorf("error staging publication %s: %w", p.row.RunKey, err)
	}

	out := &Outcome{}
	if err := p.drive(out); err != nil {
		return out, err
	}
	out.Results = results
	out.SecretLookupRateLimitSkipped = meta.SecretLookupRateLimitSkipped
	return out, nil
}

// resume continues a publication captured by a previous attempt from its
// persisted snapshot, without re-executing any external check.
func (p *Publication) resume() (*Outcome, error) {
	p.startHeartbeat()
	defer p.stopHeartbeatNow()
	out := &Outcome{Reused: true}
	if err := p.drive(out); err != nil {
		return out, err
	}
	return out, nil
}

func (p *Publication) drive(out *Outcome) error {
	results, canary, err := p.loadState()
	if err != nil {
		return err
	}
	p.canary = *canary
	p.results = results

	if p.row.Status == statusStaged {
		// Commit gate: every attachment must exist in full before the run
		// becomes visible.
		if err := p.verifyStagedObjects(); err != nil {
			_ = p.abort(fmt.Sprintf("artifact verification failed: %s", err.Error()))
			return err
		}

		created, strategyMap, err := commitRunResults(p.ctx, p.row, results, p.manifests)
		if err != nil {
			if errors.Is(err, errPublicationAlreadyCommitted) {
				fresh, loadErr := loadPublication(p.ctx, p.row.RunKey)
				if loadErr != nil {
					return loadErr
				}
				p.row = fresh
			} else {
				return fmt.Errorf("error committing publication: %w", err)
			}
		} else if p.live {
			out.TransformedChecksCreated = created
			out.CheckIDDeleteStrategyMap = strategyMap
		}
	}

	if p.row.Status == statusCommitted || p.row.Status == statusSucceeded {
		if err := p.publishOutputs(results); err != nil {
			return err
		}
	}

	if p.row.Status != statusSucceeded {
		if err := p.finalize(); err != nil {
			return err
		}
	}

	out.Results = results
	p.stopHeartbeatNow()
	return nil
}

func (p *Publication) loadState() ([]*pkg.CheckResult, *v1.Canary, error) {
	var snap Snapshot
	if p.live {
		// Already in memory.
		return p.results, &p.canary, nil
	}
	if len(p.row.Snapshot) == 0 {
		return nil, nil, fmt.Errorf("publication %s has no snapshot to resume", p.row.RunKey)
	}
	if err := jsonUnmarshal(p.row.Snapshot, &snap); err != nil {
		return nil, nil, fmt.Errorf("error decoding publication snapshot: %w", err)
	}
	if len(p.row.Artifacts) > 0 {
		if err := jsonUnmarshal(p.row.Artifacts, &p.manifests); err != nil {
			return nil, nil, fmt.Errorf("error decoding artifact manifest: %w", err)
		}
	}
	if len(p.row.HARData) > 0 {
		p.harData = p.row.HARData
	}
	p.harFilename = snap.HARFilename
	p.metrics = snap.EvaluatedMetrics
	canary, results, err := snap.restore(p.row.RunTime)
	if err != nil {
		return nil, nil, err
	}
	return results, canary, nil
}

// ---- staging (hooks) -------------------------------------------------------

func (p *Publication) RunTime() time.Time { return p.row.RunTime }

func (p *Publication) DeferMetricsExports() bool { return true }

func (p *Publication) RecordEvaluatedMetrics(_ *pkg.CheckResult, evaluated []pkg.Metric) {
	p.metrics = append(p.metrics, evaluated...)
}

func (p *Publication) StageHAR(data []byte, filename string) {
	p.harData = data
	p.harFilename = filename
}

func (p *Publication) StageArtifacts(ctx dutycontext.Context, connection models.Connection, results pkg.Results) error {
	fs, err := artifactslib.GetFSForConnection(ctx, connection)
	if err != nil {
		return fmt.Errorf("error getting filesystem for connection: %w", err)
	}
	defer fs.Close()

	var manifests []ArtifactManifest
	for _, r := range results {
		if len(r.Artifacts) == 0 {
			continue
		}
		checkIDRaw := r.Canary.GetCheckID(r.Check.GetName())
		checkID, err := uuid.Parse(checkIDRaw)
		if err != nil {
			return fmt.Errorf("error parsing checkID %s: %w", checkIDRaw, err)
		}
		for _, a := range r.Artifacts {
			// Object layout keeps the historical convention, partitioned by
			// the run's fixed identity time so retries address the same key.
			key := filepath.Join("checks", checkID.String(), fmt.Sprintf("%d", p.row.RunTime.UnixNano()), a.Path)
			vo, err := writeVerifiedObject(ctx, fs, key, a)
			if err != nil {
				return err
			}
			manifests = append(manifests, ArtifactManifest{
				CheckID:      checkID,
				ConnectionID: connection.ID,
				ObjectKey:    key,
				Filename:     vo.name,
				ContentType:  vo.contentType,
				Size:         vo.size,
				Checksum:     vo.checksum,
			})
		}
	}
	p.manifests = append(p.manifests, manifests...)
	return nil
}

func (p *Publication) persistStage() error {
	snap, err := buildSnapshot(p.canary, p.results, p.manifests, p.metrics, p.harFilename)
	if err != nil {
		return err
	}
	snapshotJSON, err := jsonMarshal(snap)
	if err != nil {
		return err
	}
	manifestJSON, err := jsonMarshal(p.manifests)
	if err != nil {
		return err
	}

	return p.ctx.DB().Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&CheckRunPublication{}).
			Where("id = ? AND status = ?", p.row.ID, statusExecuting).
			Updates(map[string]any{
				"status":       statusStaged,
				"snapshot":     snapshotJSON,
				"artifacts":    manifestJSON,
				"har_data":     p.harData,
				"har_filename": p.harFilename,
				"updated_at":   gorm.Expr("NOW()"),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("publication %s is no longer in executing state", p.row.RunKey)
		}
		p.row.Status = statusStaged
		p.row.Snapshot = snapshotJSON
		p.row.Artifacts = manifestJSON
		p.row.HARData = p.harData
		p.row.HARFilename = p.harFilename
		return nil
	})
}

// verifyStagedObjects reconciles every staged object with object storage.
func (p *Publication) verifyStagedObjects() error {
	if len(p.manifests) == 0 {
		return nil
	}
	if checks.DefaultArtifactConnection == "" {
		return fmt.Errorf("artifact connection no longer configured")
	}
	connection, err := p.ctx.HydrateConnectionByURL(checks.DefaultArtifactConnection)
	if err != nil {
		return fmt.Errorf("error getting artifact connection: %w", err)
	}
	if connection == nil {
		return fmt.Errorf("artifact connection %s not found", checks.DefaultArtifactConnection)
	}
	fs, err := artifactslib.GetFSForConnection(p.ctx, *connection)
	if err != nil {
		return err
	}
	defer fs.Close()

	for _, m := range p.manifests {
		if err := reconcileObject(fs, m.ObjectKey, m.Size); err != nil {
			return err
		}
	}
	return nil
}

// ---- outputs (each independently compare-and-set replayable) ---------------

func (p *Publication) publishOutputs(results []*pkg.CheckResult) error {
	applicable := k8sApplicable(p.canary)

	// Metrics output: claim first (at-most-once counters), then emit custom
	// metrics and record the aggregate canary metrics while building the
	// kubernetes payload.
	if p.row.MetricsPublishedAt == nil {
		claimed, err := p.claim("metrics_published_at")
		if err != nil {
			return err
		}
		if claimed {
			p.emitMetrics(results)
			if applicable && len(p.row.K8sPayload) == 0 {
				if err := p.buildAndStorePayload(results); err != nil {
					logger.Errorf("error building kubernetes status payload: %v", err)
				}
			}
		}
	}

	// Kubernetes status output.
	if applicable {
		if p.row.K8sStatusPublishedAt == nil {
			if len(p.row.K8sPayload) == 0 {
				// The metrics owner crashed after claiming but before building
				// the payload. Rebuild it; this narrow window may re-record
				// aggregate counters, which is preferred over never reporting.
				if err := p.buildAndStorePayload(results); err != nil {
					return err
				}
			}
			claimed, err := p.claim("k8s_status_published_at")
			if err != nil {
				return err
			}
			if claimed {
				var payload K8sStatusPayload
				if err := jsonUnmarshal(p.row.K8sPayload, &payload); err != nil {
					p.resetClaim("k8s_status_published_at")
					return fmt.Errorf("error decoding kubernetes payload: %w", err)
				}
				K8sStatusChannel <- payload
			}
		}
	} else if p.row.K8sStatusPublishedAt == nil {
		// Not a kubernetes-sourced run (or status channel disabled): the
		// output does not apply.
		if err := p.confirmNA("k8s_status_published_at"); err != nil {
			return err
		}
	}

	// HAR output: local file plus the verified object-store copy when an
	// artifact connection is configured.
	if len(p.row.HARData) > 0 {
		if p.row.HARPublishedAt == nil {
			claimed, err := p.claim("har_published_at")
			if err != nil {
				return err
			}
			if claimed {
				if err := p.publishHAR(); err != nil {
					// HAR writes are idempotent: allow the next driver to
					// replay this output only.
					p.resetClaim("har_published_at")
					return err
				}
			}
		}
	} else if p.row.HARPublishedAt == nil {
		if err := p.confirmNA("har_published_at"); err != nil {
			return err
		}
	}

	return nil
}

func (p *Publication) emitMetrics(_ []*pkg.CheckResult) {
	canaryCtx := canarycontext.New(p.ctx, p.canary)
	canaryCtx.Publication = p
	checks.EmitMetrics(canaryCtx, p.metrics)
}

func (p *Publication) buildAndStorePayload(results []*pkg.CheckResult) error {
	payload := BuildK8sStatusPayload(p.ctx, p.canary, results, p.row.RunTime, p.row.ID.String())
	payloadJSON, err := jsonMarshal(payload)
	if err != nil {
		return err
	}
	if err := p.ctx.DB().Model(&CheckRunPublication{}).Where("id = ?", p.row.ID).
		Updates(map[string]any{"k8s_payload": payloadJSON, "updated_at": gorm.Expr("NOW()")}).Error; err != nil {
		return err
	}
	p.row.K8sPayload = payloadJSON
	return nil
}

func (p *Publication) publishHAR() error {
	location := p.ctx.Properties().String("http.har.location", ".")
	if err := os.MkdirAll(location, 0o755); err != nil {
		return fmt.Errorf("error creating HAR directory %s: %w", location, err)
	}
	path := filepath.Join(location, p.row.HARFilename)
	if err := os.WriteFile(path, p.row.HARData, 0o644); err != nil {
		return fmt.Errorf("error writing HAR file %s: %w", path, err)
	}

	harChecksum := sha256Hex(p.row.HARData)
	harPath := ""
	if checks.DefaultArtifactConnection != "" {
		connection, err := p.ctx.HydrateConnectionByURL(checks.DefaultArtifactConnection)
		if err != nil {
			return fmt.Errorf("error getting artifact connection for HAR: %w", err)
		}
		if connection != nil {
			fs, err := artifactslib.GetFSForConnection(p.ctx, *connection)
			if err != nil {
				return err
			}
			defer fs.Close()

			key := filepath.Join("har", p.canary.Namespace, p.canary.Name, p.row.HARFilename)
			if _, err := writeVerifiedObject(p.ctx, fs, key, artifactslib.Artifact{
				ContentType: "application/json",
				Path:        key,
				Content:     io.NopCloser(bytes.NewReader(p.row.HARData)),
			}); err != nil {
				return err
			}
			harPath = key
		}
	}

	return p.ctx.DB().Model(&CheckRunPublication{}).Where("id = ?", p.row.ID).
		Updates(map[string]any{
			"har_path":     harPath,
			"har_checksum": harChecksum,
			"har_size":     len(p.row.HARData),
			"updated_at":   gorm.Expr("NOW()"),
		}).Error
}

// claim performs the compare-and-set transition of an output confirmation
// column from NULL to set. true means this caller owns the output exactly
// once.
func (p *Publication) claim(column string) (bool, error) {
	res := p.ctx.DB().Model(&CheckRunPublication{}).
		Where("id = ? AND "+column+" IS NULL", p.row.ID).
		Updates(map[string]any{column: gorm.Expr("NOW()"), "updated_at": gorm.Expr("NOW()")})
	if res.Error != nil {
		return false, fmt.Errorf("error claiming output %s: %w", column, res.Error)
	}
	if res.RowsAffected > 0 {
		now := time.Now()
		p.setOutputTime(column, &now)
		return true, nil
	}
	// Another driver claimed it; refresh our view so the loop terminates.
	fresh, err := loadPublication(p.ctx, p.row.RunKey)
	if err == nil {
		p.row = fresh
	}
	return false, nil
}

func (p *Publication) resetClaim(column string) {
	if err := p.ctx.DB().Model(&CheckRunPublication{}).Where("id = ?", p.row.ID).
		Update(column, nil).Error; err != nil {
		logger.Errorf("error resetting publication output %s: %v", column, err)
	}
	p.setOutputTime(column, nil)
}

func (p *Publication) confirmNA(column string) error {
	return p.ctx.DB().Model(&CheckRunPublication{}).Where("id = ?", p.row.ID).
		Update(column, gorm.Expr("NOW()")).Error
}

func (p *Publication) setOutputTime(column string, t *time.Time) {
	switch column {
	case "metrics_published_at":
		p.row.MetricsPublishedAt = t
	case "har_published_at":
		p.row.HARPublishedAt = t
	case "k8s_status_published_at":
		p.row.K8sStatusPublishedAt = t
	}
}

func (p *Publication) finalize() error {
	res := p.ctx.DB().Model(&CheckRunPublication{}).
		Where("id = ? AND status = ?", p.row.ID, statusCommitted).
		Updates(map[string]any{"status": statusSucceeded, "finalized_at": gorm.Expr("NOW()"), "updated_at": gorm.Expr("NOW()")})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		p.row.Status = statusSucceeded
		now := time.Now()
		p.row.FinalizedAt = &now
	}
	return nil
}

func (p *Publication) abort(reason string) error {
	p.stopHeartbeatNow()
	return p.ctx.DB().Model(&CheckRunPublication{}).
		Where("id = ? AND status IN ?", p.row.ID, []string{statusExecuting, statusStaged}).
		Updates(map[string]any{
			"status":       statusAborted,
			"abort_reason": reason,
			"finalized_at": gorm.Expr("NOW()"),
			"updated_at":   gorm.Expr("NOW()"),
		}).Error
}

// MarkK8sStatusPending resets the kubernetes output confirmation when a
// status patch failed at the controller, so only that output is replayed.
func MarkK8sStatusPending(ctx dutycontext.Context, publicationID string) {
	markK8sStatus(ctx, publicationID, nil)
}

// MarkK8sStatusConfirmed marks the kubernetes output as done when the target
// canary no longer exists and the status has nowhere to be applied.
func MarkK8sStatusConfirmed(ctx dutycontext.Context, publicationID string) {
	markK8sStatus(ctx, publicationID, gorm.Expr("NOW()"))
}

func markK8sStatus(ctx dutycontext.Context, publicationID string, value any) {
	id, err := uuid.Parse(publicationID)
	if err != nil {
		return
	}
	if err := ctx.DB().Model(&CheckRunPublication{}).Where("id = ?", id).
		Update("k8s_status_published_at", value).Error; err != nil {
		logger.Errorf("error updating kubernetes status confirmation: %v", err)
	}
}

func (p *Publication) startHeartbeat() {
	p.stopHeartbeat = make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatEvery)
		defer ticker.Stop()
		for {
			select {
			case <-p.stopHeartbeat:
				return
			case <-ticker.C:
				if err := p.ctx.DB().Model(&CheckRunPublication{}).
					Where("id = ? AND owner = ?", p.row.ID, ownerID()).
					Update("lease_until", gorm.Expr("NOW() + (? || ' seconds')::interval", strconv.Itoa(int(leaseDuration.Seconds())))).Error; err != nil {
					logger.Tracef("publication lease heartbeat failed: %v", err)
				}
			}
		}
	}()
}

func (p *Publication) stopHeartbeatNow() {
	p.stopped.Do(func() {
		if p.stopHeartbeat != nil {
			close(p.stopHeartbeat)
		}
	})
}

func ptrTime(t time.Time) *time.Time { return &t }
