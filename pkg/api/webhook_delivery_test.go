package api_test

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/pkg/db"
	"github.com/flanksource/canary-checker/pkg/webhook"
	"github.com/flanksource/commons/http"
	"github.com/flanksource/duty/models"
	"github.com/flanksource/duty/types"
	"github.com/google/uuid"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

func makeDeliveryCanary(name, token string) *models.Canary {
	spec := v1.CanarySpec{
		Webhook: &v1.WebhookCheck{
			Description: v1.Description{Name: name},
			Templatable: v1.Templatable{
				Transform: v1.Template{
					Expression: `
					results.json.alerts.map(r,
						{
							'name': r.name + r.fingerprint,
							'labels': r.labels,
							'icon': 'alert',
							'message': r.annotations.summary,
							'description': r.annotations.description,
							'deletedAt': has(r.endsAt) ? r.endsAt : null,
						}
					).toJSON()`,
				},
			},
		},
	}
	if token != "" {
		spec.Webhook.Token = &types.EnvVar{ValueStatic: token}
	}

	b, err := json.Marshal(spec)
	Expect(err).To(BeNil())
	var specJSON types.JSON
	Expect(json.Unmarshal(b, &specJSON)).To(BeNil())

	m := &models.Canary{ID: uuid.New(), Spec: specJSON, Name: name + "-canary"}
	Expect(ctx.DB().Create(m).Error).To(BeNil())
	_, err = db.GetAllCanariesForSync(ctx, "")
	Expect(err).To(BeNil())
	deliveryCanaryIDs = append(deliveryCanaryIDs, m.ID)
	return m
}

func updateDeliveryCanaryToken(m *models.Canary, token string) {
	// Re-marshal preserving the transform: load the existing spec, swap token.
	var existing v1.CanarySpec
	Expect(json.Unmarshal(m.Spec, &existing)).To(BeNil())
	if token == "" {
		existing.Webhook.Token = nil
	} else {
		existing.Webhook.Token = &types.EnvVar{ValueStatic: token}
	}
	b, err := json.Marshal(existing)
	Expect(err).To(BeNil())
	Expect(ctx.DB().Table("canaries").Where("id = ?", m.ID).Update("spec", b).Error).To(BeNil())
	m.Spec = b
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	Expect(err).To(BeNil())
	return b
}

func deliveryAlert(status, name, fingerprint, startsAt string, endsAt *time.Time, annotations map[string]string) Alert {
	return Alert{
		Status:      status,
		Name:        name,
		Labels:      map[string]string{"alertName": name},
		Annotations: annotations,
		StartsAt:    startsAt,
		EndsAt:      endsAt,
		Fingerprint: fingerprint,
	}
}

func statusCountForCheck(checkName string) int {
	var count int
	Expect(ctx.DB().Raw(`
		SELECT count(*) FROM check_statuses cs
		JOIN checks c ON c.id = cs.check_id
		WHERE c.name = ?`, checkName).Scan(&count).Error).To(BeNil())
	return count
}

func receiptStatus(eventID string) string {
	var status string
	Expect(ctx.DB().Raw(`SELECT status FROM webhook_event_receipts WHERE event_id = ?`, eventID).Scan(&status).Error).To(BeNil())
	return status
}

var deliveryCanaryIDs []uuid.UUID

var _ = ginkgo.Describe("API Webhook delivery convergence", ginkgo.Ordered, func() {
	var c *http.Client

	ginkgo.BeforeAll(func() {
		deliveryCanaryIDs = nil
		c = http.NewClient().
			BaseURL(fmt.Sprintf("http://localhost:%d", testEchoServerPort)).
			Header("Content-Type", "application/json")
	})

	// Hard-remove all data created by this describe so its randomized order
	// relative to the legacy suite does not pollute suite-wide check counts.
	ginkgo.AfterAll(func() {
		for _, id := range deliveryCanaryIDs {
			_ = ctx.DB().Exec(`DELETE FROM check_statuses WHERE check_id IN (SELECT id FROM checks WHERE canary_id = ?)`, id).Error
			_ = ctx.DB().Exec(`DELETE FROM checks_unlogged WHERE canary_id = ?`, id).Error
			_ = ctx.DB().Exec(`DELETE FROM checks WHERE canary_id = ?`, id).Error
			_ = ctx.DB().Exec(`DELETE FROM webhook_event_receipts WHERE canary_id = ?`, id).Error
			_ = ctx.DB().Exec(`DELETE FROM canaries WHERE id = ?`, id).Error
		}
	})

	ginkgo.It("converges redelivered identical batches without duplicate state", func() {
		_ = makeDeliveryCanary("idempotent-webhook", "secret-1")

		msg := DummyWebhookMessage{
			Version: "4",
			Alerts: []Alert{
				deliveryAlert("firing", "A", "fp-a", "2024-01-01T00:00:00Z", nil,
					map[string]string{"summary": "a", "description": "a"}),
				deliveryAlert("firing", "B", "fp-b", "2024-01-01T00:05:00Z", nil,
					map[string]string{"summary": "b", "description": "b"}),
			},
		}

		url := fmt.Sprintf("/webhook/%s?token=%s", "idempotent-webhook", "secret-1")
		for i := 0; i < 4; i++ {
			resp, err := c.R(ctx).Post(url, msg)
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(200), "delivery %d", i)
		}

		eventID := webhook.EventID("idempotent-webhook", mustJSON(msg))
		Expect(receiptStatus(eventID)).To(Equal("confirmed"))

		Expect(statusCountForCheck("A" + "fp-a")).To(Equal(1))
		Expect(statusCountForCheck("B" + "fp-b")).To(Equal(1))

		var receiptCount int
		Expect(ctx.DB().Raw(`SELECT count(*) FROM webhook_event_receipts WHERE event_id = ?`, eventID).Scan(&receiptCount).Error).To(BeNil())
		Expect(receiptCount).To(Equal(1))

		var checks []models.Check
		Expect(ctx.DB().Where("type = ?", "webhook").Where("name IN ?", []string{"Afp-a", "Bfp-b"}).Find(&checks).Error).To(BeNil())
		Expect(checks).To(HaveLen(2))
	})

	ginkgo.It("does not let duplicate or older events resurrect a resolved check", func() {
		checkName := "Cfp-c"
		firing := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("firing", "C", "fp-c", "2024-01-01T00:00:00Z", nil,
				map[string]string{"summary": "c"}),
		}}
		resolved := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("resolved", "C", "fp-c", "2024-01-01T00:00:00Z",
				lo.ToPtr(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
				map[string]string{"summary": "c resolved"}),
		}}
		// A distinct payload carrying the same resolved notification.
		resolvedDuplicate := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("resolved", "C", "fp-c", "2024-01-01T00:00:00Z",
				lo.ToPtr(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
				map[string]string{"summary": "c resolved again"}),
		}}
		// An older firing notification arriving late (out of order).
		staleFiring := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("firing", "C", "fp-c", "2023-12-31T00:00:00Z", nil,
				map[string]string{"summary": "c stale"}),
		}}

		base := "/webhook/idempotent-webhook?token=secret-1"
		post := func(msg any) int {
			resp, err := c.R(ctx).Post(base, msg)
			Expect(err).To(BeNil())
			return resp.StatusCode
		}

		Expect(post(firing)).To(Equal(200))
		Expect(post(resolved)).To(Equal(200))

		var result models.Check
		Expect(ctx.DB().Where("name = ?", checkName).First(&result).Error).To(BeNil())
		Expect(result.DeletedAt).ToNot(BeNil())
		Expect(statusCountForCheck(checkName)).To(Equal(2))

		// Exact redelivery is a confirmed no-op.
		Expect(post(resolved)).To(Equal(200))
		// A different batch with the same resolved event time is suppressed.
		Expect(post(resolvedDuplicate)).To(Equal(200))
		// An older firing must not resurrect the check.
		Expect(post(staleFiring)).To(Equal(200))

		Expect(ctx.DB().Where("name = ?", checkName).First(&result).Error).To(BeNil())
		Expect(result.DeletedAt).ToNot(BeNil())
		Expect(statusCountForCheck(checkName)).To(Equal(2), "no extra status details")
	})

	ginkgo.It("authorizes redelivery against the receive-time token generation", func() {
		m := makeDeliveryCanary("rotating-webhook", "old-token")
		msg := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("firing", "D", "fp-d", "2024-02-01T00:00:00Z", nil,
				map[string]string{"summary": "d"}),
		}}

		oldURL := "/webhook/rotating-webhook?token=old-token"
		resp, err := c.R(ctx).Post(oldURL, msg)
		Expect(err).To(BeNil())
		Expect(resp.StatusCode).To(Equal(200))

		// Rotate the token on the canary.
		updateDeliveryCanaryToken(m, "new-token")

		// The old token still completes/acknowledges the event accepted under
		// the previous generation...
		resp, err = c.R(ctx).Post(oldURL, msg)
		Expect(err).To(BeNil())
		Expect(resp.StatusCode).To(Equal(200))

		// ...an unknown token is explicitly rejected...
		resp, err = c.R(ctx).Post("/webhook/rotating-webhook?token=nope", msg)
		Expect(err).To(BeNil())
		Expect(resp.StatusCode).To(Equal(401))

		// ...while the current generation token also works.
		resp, err = c.R(ctx).Post("/webhook/rotating-webhook?token=new-token", msg)
		Expect(err).To(BeNil())
		Expect(resp.StatusCode).To(Equal(200))
	})

	ginkgo.It("accepts deliveries without a configured token (legacy auth behavior)", func() {
		makeDeliveryCanary("open-webhook", "")
		msg := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("firing", "E", "fp-e", "2024-03-01T00:00:00Z", nil,
				map[string]string{"summary": "e"}),
		}}
		for i := 0; i < 2; i++ {
			resp, err := c.R(ctx).Post("/webhook/open-webhook", msg)
			Expect(err).To(BeNil())
			Expect(resp.StatusCode).To(Equal(200))
		}
		Expect(statusCountForCheck("Efp-e")).To(Equal(1))
	})

	ginkgo.It("keeps the legacy path for non-JSON payloads", func() {
		makeDeliveryCanary("plain-webhook", "plain-token")
		plain := http.NewClient().
			BaseURL(fmt.Sprintf("http://localhost:%d", testEchoServerPort)).
			Header("Content-Type", "text/plain")
		resp, err := plain.R(ctx).Post("/webhook/plain-webhook?token=plain-token", "not-json")
		Expect(err).To(BeNil())
		Expect(resp.StatusCode).To(Equal(200))
	})

	ginkgo.It("converges concurrent redeliveries from multiple instances", func() {
		_ = makeDeliveryCanary("concurrent-webhook", "parallel-token")
		msg := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("firing", "F", "fp-f", "2024-04-01T00:00:00Z", nil,
				map[string]string{"summary": "f"}),
		}}

		var wg sync.WaitGroup
		statuses := make(chan int, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := c.R(ctx).Post("/webhook/concurrent-webhook?token=parallel-token", msg)
				Expect(err).To(BeNil())
				statuses <- resp.StatusCode
			}()
		}
		wg.Wait()
		close(statuses)
		for s := range statuses {
			Expect(s).To(Equal(200))
		}

		Expect(statusCountForCheck("Ffp-f")).To(Equal(1))
		eventID := webhook.EventID("concurrent-webhook", mustJSON(msg))
		Expect(receiptStatus(eventID)).To(Equal("confirmed"))
	})

	ginkgo.It("resumes an interrupted event from unconfirmed checks without duplicates", func() {
		_ = makeDeliveryCanary("recovery-webhook", "recovery-token")
		msg := DummyWebhookMessage{Version: "4", Alerts: []Alert{
			deliveryAlert("firing", "G", "fp-g", "2024-05-01T00:00:00Z", nil,
				map[string]string{"summary": "g"}),
		}}
		resp, err := c.R(ctx).Post("/webhook/recovery-webhook?token=recovery-token", msg)
		Expect(err).To(BeNil())
		Expect(resp.StatusCode).To(Equal(200))
		Expect(statusCountForCheck("Gfp-g")).To(Equal(1))

		eventID := webhook.EventID("recovery-webhook", mustJSON(msg))

		// Simulate a crash before confirmation: rows look unconfirmed and old.
		Expect(ctx.DB().Exec(`
			UPDATE webhook_event_checks SET published = FALSE, metrics_exported = FALSE, skipped_stale = FALSE
			WHERE event_id = ?`, eventID).Error).To(BeNil())
		Expect(ctx.DB().Exec(`
			UPDATE webhook_event_receipts
			SET status = 'received', received_at = NOW() - INTERVAL '2 minutes', confirmed_at = NULL, published_at = NULL
			WHERE event_id = ?`, eventID).Error).To(BeNil())

		Expect(webhook.RecoverPending(ctx, 10)).To(BeNil())

		Expect(receiptStatus(eventID)).To(Equal("confirmed"))
		Expect(statusCountForCheck("Gfp-g")).To(Equal(1), "resume must not insert duplicate details")
	})
})
