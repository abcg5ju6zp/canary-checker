package pkg

import (
	"time"

	dutycontext "github.com/flanksource/duty/context"
	"github.com/flanksource/duty/models"
)

// RunPublicationHooks binds a single check run's side effects (artifact
// uploads, HAR, metrics) to a recoverable publication record.
//
// When a non-nil implementation is attached to the run context, RunChecks
// diverges from its fire-and-forget behavior: artifacts are staged and
// verified before the run results are allowed to take effect, HAR rendering
// is deferred to the post-commit publication outputs, and check metrics are
// collected instead of being emitted during execution. The implementation
// lives in pkg/publication; the interface is declared here to avoid an
// import cycle between the checks and publication packages.
type RunPublicationHooks interface {
	// RunTime is the fixed identity time of the run. All persisted status
	// rows, artifact partitions and generated filenames derive from it, making
	// every publication step idempotent across retries and restarts.
	RunTime() time.Time

	// DeferMetricsExports reports whether ExportCheckMetrics must sink
	// evaluated metrics into the publication instead of emitting them to
	// Prometheus immediately.
	DeferMetricsExports() bool

	// RecordEvaluatedMetrics stores the metrics evaluated for one result
	// (result-attached metrics plus spec-templated metrics) so they can be
	// emitted exactly once, after the result commit is confirmed.
	RecordEvaluatedMetrics(result *CheckResult, evaluated []Metric)

	// StageArtifacts uploads every artifact produced by the run to object
	// storage, verifies the written content (size and streamed sha256) and
	// records a manifest for it. A returned error means the artifact content
	// is incomplete or unverifiable and the run results must not be
	// published. Repeated calls first reconcile objects that already exist.
	StageArtifacts(ctx dutycontext.Context, connection models.Connection, results Results) error

	// StageHAR records the rendered HAR bytes for the run. HAR is published
	// (local file and, when configured, object storage) only after the
	// result commit is confirmed.
	StageHAR(data []byte, filename string)
}
