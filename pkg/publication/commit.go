package publication

import (
	"fmt"
	"time"

	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/cache"
	"github.com/flanksource/canary-checker/pkg/db"
	"github.com/flanksource/duty/context"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SaveResults persists a run's results without a bound publication. This is
// the legacy path used by runs without artifacts or HAR; behavior is
// unchanged from when it lived in pkg/jobs/canary.
func SaveResults(ctx context.Context, results []*pkg.CheckResult) ([]string, map[string]string, error) {
	var transformedChecksCreated []string
	// Transformed checks have a delete strategy
	// On deletion they can either be marked healthy, unhealthy or left as is
	checkIDDeleteStrategyMap := make(map[string]string)

	if len(results) == 0 {
		return transformedChecksCreated, checkIDDeleteStrategyMap, nil
	}

	tx := ctx.DB().Begin()
	if tx.Error != nil {
		return nil, nil, fmt.Errorf("error starting transaction: %w", tx.Error)
	}
	defer tx.Rollback()

	for _, result := range results {
		if result.HasCanary() {
			if _, err := persistOneResult(ctx, tx, result, nil); err != nil {
				return nil, nil, err
			}
			continue
		}
		transformedCheckID, err := persistOneResult(ctx, tx, result, nil)
		if err != nil {
			return nil, nil, err
		}
		transformedChecksCreated = append(transformedChecksCreated, transformedCheckID)
		checkIDDeleteStrategyMap[transformedCheckID] = result.Check.GetTransformDeleteStrategy()
	}

	return transformedChecksCreated, checkIDDeleteStrategyMap, tx.Commit().Error
}

func persistOneResult(ctx context.Context, tx *gorm.DB, result *pkg.CheckResult, runTime *time.Time) (string, error) {
	if result.HasCanary() {
		for _, can := range result.CanaryResult {
			m := can.ToModel()
			canaryID, err := uuid.Parse(result.Canary.GetPersistedID())
			if err != nil {
				return "", fmt.Errorf("error getting canary_id: %w", err)
			}
			checkID, err := cache.PostgresCache.GetCheckID(ctx, canaryID, result.Check.GetType(), result.Check.GetName())
			if err != nil {
				return "", fmt.Errorf("error getting check_id: %w", err)
			}
			m.Source = fmt.Sprintf("check=%s", checkID)
			if _, _, err := db.PersistCanaryModel(ctx.WithDB(tx, ctx.Pool()), m); err != nil {
				return "", fmt.Errorf("error saving canary: %w", err)
			}
		}
		return "", nil
	}

	status := pkg.CheckStatusFromResult(*result)
	if runTime != nil {
		// A bound publication fixes every status row of a run to the run's
		// identity second, so retries collapse onto the same
		// (check_id, time) row instead of writing duplicates.
		status.Time = runTime.UTC().Format(time.RFC3339)
	}

	transformedCheckID, err := cache.PostgresCache.Add(
		ctx.WithDB(tx, ctx.Pool()),
		pkg.FromV1(result.Canary, result.Check),
		status,
	)
	if err != nil {
		return "", fmt.Errorf("error adding check to cache: %w", err)
	}

	// Establish relationship with components & configs
	if err := FormCheckRelationships(ctx.WithDB(tx, ctx.Pool()), result); err != nil {
		ctx.Logger.Named(result.Name).Errorf("error forming check relationships: %v", err)
	}
	return transformedCheckID, nil
}

// commitRunResults is the atomic publication gate: in one database
// transaction it persists check statuses, artifact metadata rows,
// relationships and flips the publication to "committed". It is safe to
// re-run after a lost commit response: every insert is idempotent and the
// state flip is conditional on still being "staged", so a concurrent or
// repeated driver cannot publish twice.
func commitRunResults(ctx context.Context, row *CheckRunPublication, results []*pkg.CheckResult, manifests []ArtifactManifest) ([]string, map[string]string, error) {
	var transformedChecksCreated []string
	checkIDDeleteStrategyMap := make(map[string]string)

	tx := ctx.DB().Begin()
	if tx.Error != nil {
		return nil, nil, fmt.Errorf("error starting transaction: %w", tx.Error)
	}
	defer tx.Rollback()

	runTime := row.RunTime
	for _, result := range results {
		transformedCheckID, err := persistOneResult(ctx, tx, result, &runTime)
		if err != nil {
			return nil, nil, err
		}
		if result.HasCanary() {
			continue
		}
		if transformedCheckID != "" {
			transformedChecksCreated = append(transformedChecksCreated, transformedCheckID)
			checkIDDeleteStrategyMap[transformedCheckID] = result.Check.GetTransformDeleteStrategy()
		}
	}

	// Artifact metadata joins the run only now, in the same transaction as
	// the check statuses. An earlier crash left the object in storage but no
	// row; a later rollback leaves no row without a status.
	for i := range manifests {
		if err := insertArtifactRow(tx, row.ID, runTime, manifests[i]); err != nil {
			return nil, nil, fmt.Errorf("error persisting artifact metadata for %s: %w", manifests[i].ObjectKey, err)
		}
	}

	// Flip the publication state inside the same transaction. The
	// status='staged' predicate makes the gate single-use: a losing driver
	// whose transaction reaches this point second commits nothing.
	res := tx.Model(&CheckRunPublication{}).
		Where("id = ? AND status = ?", row.ID, statusStaged).
		Updates(map[string]any{"status": statusCommitted, "results_committed_at": gorm.Expr("NOW()"), "updated_at": gorm.Expr("NOW()")})
	if res.Error != nil {
		return nil, nil, fmt.Errorf("error confirming publication: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, nil, errPublicationAlreadyCommitted
	}

	if err := tx.Commit().Error; err != nil {
		return nil, nil, fmt.Errorf("error committing publication: %w", err)
	}

	row.Status = statusCommitted
	t := time.Now()
	row.ResultsCommittedAt = &t
	return transformedChecksCreated, checkIDDeleteStrategyMap, nil
}

var errPublicationAlreadyCommitted = fmt.Errorf("publication already committed")

// artifactRowID is deterministic in (publication, object key) so a retried
// commit never creates duplicate artifact rows.
func artifactRowID(publicationID uuid.UUID, objectKey string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("check-run-publication:"+publicationID.String()+":"+objectKey))
}

func insertArtifactRow(tx *gorm.DB, publicationID uuid.UUID, runTime time.Time, m ArtifactManifest) error {
	id := artifactRowID(publicationID, m.ObjectKey)
	return tx.Exec(`
INSERT INTO artifacts (id, check_id, check_time, connection_id, path, filename, size, content_type, checksum, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
ON CONFLICT (id) DO NOTHING`,
		id, m.CheckID, runTime, m.ConnectionID, m.ObjectKey, m.Filename, m.Size, m.ContentType, m.Checksum,
	).Error
}
