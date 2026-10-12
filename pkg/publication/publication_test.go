package publication

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/checks"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/db"
	"github.com/flanksource/duty/models"
	"github.com/flanksource/duty/shell"
	"github.com/flanksource/duty/types"
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/gomega"

	ginkgo "github.com/onsi/ginkgo/v2"
)

var _ = ginkgo.Describe("Check run publication", ginkgo.Ordered, func() {
	var artifactDir string
	var connection *models.Connection

	ginkgo.BeforeAll(func() {
		var err error
		artifactDir, err = os.MkdirTemp("", "canary-publication-*")
		Expect(err).To(BeNil())

		connection = &models.Connection{
			ID:        uuid.New(),
			Name:      "publication-test-" + uuid.NewString()[:8],
			Namespace: "default",
			Source:    models.SourceConfigFile,
			Type:      models.ConnectionTypeFolder,
			Properties: types.JSONStringMap{
				"path": artifactDir,
			},
		}
		Expect(DefaultContext.DB().Create(connection).Error).To(BeNil())
		checks.DefaultArtifactConnection = "connection://default/" + connection.Name
	})

	ginkgo.AfterAll(func() {
		checks.DefaultArtifactConnection = ""
		_ = os.RemoveAll(artifactDir)
	})

	persist := func(name string, spec v1.CanarySpec) (pkg.Canary, v1.Canary) {
		m, _, err := db.PersistCanary(DefaultContext, v1.Canary{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec:       spec,
		}, "test")
		Expect(err).To(BeNil())
		v1Canary, err := m.ToV1()
		Expect(err).To(BeNil())
		return *m, *v1Canary
	}

	ginkgo.It("gates only runs that can produce attachments or HAR", func() {
		artifactCanary := v1.Canary{Spec: v1.CanarySpec{
			Exec: []v1.ExecCheck{{Artifacts: []shell.Artifact{{Path: "/dev/stdout"}}}},
		}}
		plainCanary := v1.Canary{Spec: v1.CanarySpec{HTTP: []v1.HTTPCheck{{Endpoint: "http://example.com"}}}}

		Expect(ShouldGate(artifactCanary, false)).To(BeTrue())
		Expect(ShouldGate(plainCanary, true)).To(BeTrue())

		checks.DefaultArtifactConnection = ""
		Expect(ShouldGate(artifactCanary, false)).To(BeFalse())
		Expect(ShouldGate(plainCanary, false)).To(BeFalse())
		checks.DefaultArtifactConnection = "connection://default/" + connection.Name
	})

	ginkgo.It("uses a stable scheduled run key within a schedule slot", func() {
		canary := v1.Canary{Spec: v1.CanarySpec{Schedule: "@every 30s"}}
		now := time.Now()
		id := uuid.New()
		slot := scheduledSlot(canary, now)
		k1 := ScheduledRunKey(id, canary, slot.Add(1*time.Second))
		k2 := ScheduledRunKey(id, canary, slot.Add(25*time.Second))
		Expect(k1).To(Equal(k2))
		k3 := ScheduledRunKey(id, canary, slot.Add(35*time.Second))
		Expect(k3).ToNot(Equal(k1))
	})

	ginkgo.It("publishes an exec run with its attachment and is idempotent", func() {
		spec := v1.CanarySpec{
			Schedule: "@every 1h",
			Exec: []v1.ExecCheck{{
				Description: v1.Description{Name: "artifact-exec"},
				Script:      "echo hello-artifact",
				Artifacts:   []shell.Artifact{{Path: "/dev/stdout"}},
			}},
		}
		m, v1Canary := persist("pub-exec-"+uuid.NewString()[:8], spec)
		checkID := v1Canary.GetCheckID("artifact-exec")
		Expect(checkID).ToNot(BeEmpty())

		runKey := "test-exec-" + uuid.NewString()
		outcome, err := RunGated(DefaultContext, m, v1Canary, runKey, TriggerScheduled)
		Expect(err).To(BeNil())
		Expect(outcome).ToNot(BeNil())
		Expect(outcome.Skipped).To(BeFalse())
		Expect(outcome.Results).To(HaveLen(1))

		row, err := loadPublication(DefaultContext, runKey)
		Expect(err).To(BeNil())
		Expect(row.Status).To(Equal(statusSucceeded))
		Expect(row.ResultsCommittedAt).ToNot(BeNil())
		Expect(row.MetricsPublishedAt).ToNot(BeNil())
		Expect(row.HARPublishedAt).ToNot(BeNil())
		Expect(row.K8sStatusPublishedAt).ToNot(BeNil())

		var statusCount int64
		Expect(DefaultContext.DB().Raw(`SELECT count(*) FROM check_statuses WHERE check_id = ?`, checkID).Scan(&statusCount).Error).To(BeNil())
		Expect(statusCount).To(BeNumerically(">=", 1))

		var artifactCount int64
		Expect(DefaultContext.DB().Raw(`SELECT count(*) FROM artifacts WHERE check_id = ?`, checkID).Scan(&artifactCount).Error).To(BeNil())
		Expect(artifactCount).To(Equal(int64(1)))

		var artifact models.Artifact
		Expect(DefaultContext.DB().Where("check_id = ?", checkID).First(&artifact).Error).To(BeNil())
		Expect(artifact.Checksum).ToNot(BeEmpty())
		Expect(artifact.Size).To(BeNumerically(">", 0))

		objectPath := filepath.Join(artifactDir, "checks", checkID, fmt.Sprintf("%d", row.RunTime.UnixNano()), "stdout")
		data, err := os.ReadFile(objectPath)
		Expect(err).To(BeNil())
		// /dev/stdout artifacts contain the command's (trimmed) stdout.
		Expect(string(data)).To(Equal("hello-artifact"))

		// Re-driving the same run key must not duplicate anything.
		outcome2, err := RunGated(DefaultContext, m, v1Canary, runKey, TriggerScheduled)
		Expect(err).To(BeNil())
		Expect(outcome2.Reused).To(BeTrue())

		Expect(DefaultContext.DB().Raw(`SELECT count(*) FROM artifacts WHERE check_id = ?`, checkID).Scan(&artifactCount).Error).To(BeNil())
		Expect(artifactCount).To(Equal(int64(1)))
	})

	ginkgo.It("recovers a staged publication without re-running checks", func() {
		spec := v1.CanarySpec{
			Schedule: "@every 1h",
			HTTP:     []v1.HTTPCheck{{Description: v1.Description{Name: "recovery-http"}, Endpoint: "http://example.com"}},
		}
		m, v1Canary := persist("pub-recovery-"+uuid.NewString()[:8], spec)
		checkID := v1Canary.GetCheckID("recovery-http")
		checkUUID := uuid.MustParse(checkID)

		runTime := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
		result := pkg.Success(v1Canary.Spec.HTTP[0], v1Canary)
		result.Start = runTime
		result.Duration = 7

		// Pretend a previous attempt already wrote the object, then died.
		key := filepath.Join("checks", checkID, fmt.Sprintf("%d", runTime.UnixNano()), "stdout")
		fullPath := filepath.Join(artifactDir, key)
		Expect(os.MkdirAll(filepath.Dir(fullPath), 0o755)).To(BeNil())
		Expect(os.WriteFile(fullPath, []byte("recovered"), 0o644)).To(BeNil())

		manifest := ArtifactManifest{
			CheckID:      checkUUID,
			ConnectionID: connection.ID,
			ObjectKey:    key,
			Filename:     "stdout",
			ContentType:  "text/plain",
			Size:         int64(len("recovered")),
			Checksum:     "deadbeef",
		}
		snap, err := buildSnapshot(v1Canary, []*pkg.CheckResult{result}, []ArtifactManifest{manifest}, nil, "")
		Expect(err).To(BeNil())
		snapshotJSON, err := jsonMarshal(snap)
		Expect(err).To(BeNil())
		manifestJSON, err := jsonMarshal([]ArtifactManifest{manifest})
		Expect(err).To(BeNil())

		canaryID := m.ID
		lease := runTime
		row := CheckRunPublication{
			ID:             uuid.New(),
			RunKey:         "test-recovery-" + uuid.NewString(),
			CanaryID:       &canaryID,
			Source:         "test",
			Trigger:        TriggerScheduled,
			Status:         statusStaged,
			RunTime:        runTime,
			Snapshot:       snapshotJSON,
			Artifacts:      manifestJSON,
			Owner:          "dead-owner",
			LeaseUntil:     &lease,
			Attempts:       1,
			CreatedAt:      runTime,
			UpdatedAt:      runTime,
		}
		Expect(DefaultContext.DB().Create(&row).Error).To(BeNil())

		Expect(Sweep(DefaultContext)).To(BeNil())

		recovered, err := loadPublication(DefaultContext, row.RunKey)
		Expect(err).To(BeNil())
		Expect(recovered.Status).To(Equal(statusSucceeded))
		Expect(recovered.ResultsCommittedAt).ToNot(BeNil())

		var statusCount int64
		Expect(DefaultContext.DB().Raw(`SELECT count(*) FROM check_statuses WHERE check_id = ? AND time = ?`, checkID, runTime.Format(time.RFC3339)).Scan(&statusCount).Error).To(BeNil())
		Expect(statusCount).To(Equal(int64(1)))

		var artifactCount int64
		Expect(DefaultContext.DB().Raw(`SELECT count(*) FROM artifacts WHERE check_id = ? AND checksum = 'deadbeef'`, checkID).Scan(&artifactCount).Error).To(BeNil())
		Expect(artifactCount).To(Equal(int64(1)))
	})

	ginkgo.It("aborts an executing publication whose owner died before staging", func() {
		runTime := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
		lease := runTime.Add(-10 * time.Minute)
		row := CheckRunPublication{
			ID:        uuid.New(),
			RunKey:    "test-abort-" + uuid.NewString(),
			Status:    statusExecuting,
			RunTime:   runTime,
			Owner:     "dead-owner",
			LeaseUntil: &lease,
			Attempts:  1,
			CreatedAt: runTime,
			UpdatedAt: runTime,
		}
		Expect(DefaultContext.DB().Create(&row).Error).To(BeNil())

		Expect(Sweep(DefaultContext)).To(BeNil())

		recovered, err := loadPublication(DefaultContext, row.RunKey)
		Expect(err).To(BeNil())
		Expect(recovered.Status).To(Equal(statusAborted))
	})
})
