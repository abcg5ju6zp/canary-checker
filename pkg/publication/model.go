package publication

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/flanksource/canary-checker/pkg"
	dutycontext "github.com/flanksource/duty/context"
	"github.com/google/uuid"
)

// Publication statuses form the recoverable state machine of a check run.
//
//	executing -> staged -> committed -> succeeded
//	      |          |          |
//	      v          v          v
//	                 aborted (only before the commit is confirmed)
//
// executing: the publication row exists (claimed), external checks may be in
//
//	progress. Nothing externally visible has happened.
//	staged: checks finished, every artifact object is written and verified and
//	the result snapshot is persisted. The database commit has not been
//	confirmed.
//	committed: the single database transaction (check statuses, artifact
//	metadata rows, relationships, publication state) is confirmed. Only
//	individually-replayable outputs (metrics, HAR, kubernetes status) may be
//	outstanding.
//	succeeded: every applicable output is confirmed.
const (
	statusExecuting = "executing"
	statusStaged    = "staged"
	statusCommitted = "committed"
	statusSucceeded = "succeeded"
	statusAborted   = "aborted"
)

const (
	triggerScheduled = "scheduled"
	triggerRunNow    = "run_now"
)

// CheckRunPublication binds everything a single check run publishes into one
// recoverable, idempotently resumable row.
type CheckRunPublication struct {
	ID     uuid.UUID `gorm:"primaryKey"`
	RunKey string    `gorm:"column:run_key;not null;uniqueIndex"`

	CanaryID *uuid.UUID `gorm:"column:canary_id;index"`
	Source   string     `gorm:"column:source"`
	Trigger  string     `gorm:"column:trigger"`

	// Status is the current state-machine state.
	Status string `gorm:"column:status;not null;index"`

	// RunTime is the fixed identity time of the run: status rows use it as
	// their composite-PK time, artifacts as their partition/check_time, and
	// generated files as their timestamp. It is truncated to the second.
	RunTime time.Time `gorm:"column:run_time;not null"`

	// Snapshot holds the serializable result set (results, canary identity,
	// evaluated metrics). It is the input to every replay after a crash and
	// guarantees external checks are never re-executed once staged.
	Snapshot []byte `gorm:"column:snapshot;type:jsonb"`

	// Artifacts is the verified artifact object manifest (object keys, sizes,
	// sha256 checksums, content types).
	Artifacts []byte `gorm:"column:artifacts;type:jsonb"`

	// HARData holds the rendered HAR document, captured before the commit and
	// published after it, so a failed HAR publication can replay without
	// re-running the HTTP checks.
	HARData     []byte `gorm:"column:har_data;type:bytea"`
	HARFilename string `gorm:"column:har_filename"`
	HARPath     string `gorm:"column:har_path"`
	HARChecksum string `gorm:"column:har_checksum"`
	HARSize     int64  `gorm:"column:har_size"`

	// K8sPayload is the built kubernetes status payload, persisted by the
	// metrics output winner so the kubernetes output can replay on its own.
	K8sPayload []byte `gorm:"column:k8s_payload;type:jsonb"`

	// Output confirmation timestamps. Each transitions from NULL to set at
	// most once (compare-and-set), which is what makes the outputs replayable
	// without duplicating counters, rows or statuses.
	MetricsPublishedAt    *time.Time `gorm:"column:metrics_published_at"`
	HARPublishedAt        *time.Time `gorm:"column:har_published_at"`
	K8sStatusPublishedAt  *time.Time `gorm:"column:k8s_status_published_at"`
	ResultsCommittedAt    *time.Time `gorm:"column:results_committed_at"`
	FinalizedAt           *time.Time `gorm:"column:finalized_at"`
	AbortReason           string     `gorm:"column:abort_reason"`
	Owner                 string     `gorm:"column:owner"`
	LeaseUntil            *time.Time `gorm:"column:lease_until"`
	Attempts              int        `gorm:"column:attempts"`
	CreatedAt             time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time  `gorm:"column:updated_at;not null"`
}

func (CheckRunPublication) TableName() string {
	return "check_run_publications"
}

// ArtifactManifest describes one verified artifact object belonging to a run.
type ArtifactManifest struct {
	ResultIndex  int       `json:"result_index"`
	CheckID      uuid.UUID `json:"check_id"`
	ConnectionID uuid.UUID `json:"connection_id"`
	ObjectKey    string    `json:"object_key"`
	Filename     string    `json:"filename"`
	ContentType  string    `json:"content_type"`
	Size         int64     `json:"size"`
	Checksum     string    `json:"checksum"`
}

// ResultSnapshot is the serializable, replay-sufficient view of one
// CheckResult of a staged run.
type ResultSnapshot struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Transformed   bool   `json:"transformed,omitempty"`
	ParentName    string `json:"parent_name,omitempty"`
	ParentType    string `json:"parent_type,omitempty"`
	Pass          bool   `json:"pass"`
	Invalid       bool   `json:"invalid,omitempty"`
	InternalError bool   `json:"internal_error,omitempty"`
	Duration      int64  `json:"duration,omitempty"`
	Message       string `json:"message,omitempty"`
	Error         string `json:"error,omitempty"`
	// Detail is stored as raw JSON so replays reproduce check_statuses.details
	// byte-for-byte.
	Detail json.RawMessage `json:"detail,omitempty"`
	// Metrics are the result-attached metrics; EvaluatedMetrics is the flat
	// set of all metrics evaluated during execution (result metrics plus spec
	// templated metrics), stored run-wide so result folding (e.g. junit result
	// mode) cannot drop them on replay.
	Metrics      []pkg.Metric       `json:"metrics,omitempty"`
	CanaryResult []pkg.TransformedCanaryResult `json:"canary_result,omitempty"`
	Artifacts    []ArtifactManifest `json:"artifacts,omitempty"`
}

// Snapshot is the persisted replay input for an entire run.
type Snapshot struct {
	Canary           json.RawMessage  `json:"canary"`
	Results          []ResultSnapshot `json:"results"`
	HARFilename      string           `json:"har_filename,omitempty"`
	EvaluatedMetrics []pkg.Metric     `json:"evaluated_metrics,omitempty"`
}

var (
	schemaMu    sync.Mutex
	schemaReady bool
)

// EnsureSchema creates the publication table once per process. It is a local
// canary-checker table (the duty module owns the rest of the schema); using
// IF NOT EXISTS makes concurrent first-runs and mixed-version rollouts safe.
// A failed attempt is not cached, so a transient database error does not
// disable publications for the rest of the process lifetime.
func EnsureSchema(ctx dutycontext.Context) error {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if schemaReady {
		return nil
	}
	if err := ctx.DB().Exec(`
CREATE TABLE IF NOT EXISTS check_run_publications (
    id UUID PRIMARY KEY,
    run_key TEXT NOT NULL,
    canary_id UUID,
    source TEXT,
    trigger TEXT,
    status TEXT NOT NULL,
    run_time TIMESTAMPTZ NOT NULL,
    snapshot JSONB,
    artifacts JSONB,
    har_data BYTEA,
    har_filename TEXT,
    har_path TEXT,
    har_checksum TEXT,
    har_size BIGINT,
    k8s_payload JSONB,
    metrics_published_at TIMESTAMPTZ,
    har_published_at TIMESTAMPTZ,
    k8s_status_published_at TIMESTAMPTZ,
    results_committed_at TIMESTAMPTZ,
    finalized_at TIMESTAMPTZ,
    abort_reason TEXT,
    owner TEXT,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_run_publications_run_key_key UNIQUE (run_key)
);
CREATE INDEX IF NOT EXISTS idx_check_run_publications_canary ON check_run_publications(canary_id);
CREATE INDEX IF NOT EXISTS idx_check_run_publications_status ON check_run_publications(status);
`).Error; err != nil {
		return err
	}
	schemaReady = true
	return nil
}

func loadPublication(ctx dutycontext.Context, runKey string) (*CheckRunPublication, error) {
	var row CheckRunPublication
	if err := ctx.DB().Where("run_key = ?", runKey).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
