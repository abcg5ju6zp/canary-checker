package publication

import (
	"fmt"
	"strings"
	"time"

	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/db"
	"github.com/flanksource/canary-checker/pkg/metrics"
	"github.com/flanksource/canary-checker/pkg/utils"
	"github.com/flanksource/duty/context"
	dutyTypes "github.com/flanksource/duty/types"
	"github.com/samber/lo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// K8sStatusChannel receives canary status updates for the kubernetes
// controller. nil means canary status reporting is disabled (e.g. running
// outside the operator), matching the previous behavior.
var K8sStatusChannel chan K8sStatusPayload

type K8sStatusPayload struct {
	Status               v1.CanaryStatusCondition
	CheckStatus          map[string]*v1.CheckStatus
	FailEvents           []string
	LastTransitionedTime *metav1.Time
	Message              string
	ErrorMessage         string
	Uptime               string
	Latency              string
	NamespacedName       types.NamespacedName

	// PublicationID ties this payload to a bound publication so a failed
	// status patch can reset only the kubernetes output confirmation.
	PublicationID string
}

func k8sApplicable(canary v1.Canary) bool {
	return K8sStatusChannel != nil && strings.HasPrefix(canary.Annotations["source"], "kubernetes")
}

// PublishK8sStatusLegacy reproduces the pre-publication behavior for runs
// without artifacts/HAR: aggregate metrics are recorded and the status
// payload is sent unconditionally (no replay bookkeeping).
func PublishK8sStatusLegacy(ctx context.Context, canary v1.Canary, results []*pkg.CheckResult, now time.Time) {
	if len(results) == 0 || !k8sApplicable(canary) {
		return
	}
	payload := BuildK8sStatusPayload(ctx, canary, results, now, "")
	K8sStatusChannel <- payload
}

// BuildK8sStatusPayload aggregates the run results into the CRD status
// payload. Recording aggregate canary metrics is part of building the
// payload and therefore happens exactly once per run (the metrics output
// winner of a bound publication).
func BuildK8sStatusPayload(ctx context.Context, canary v1.Canary, results []*pkg.CheckResult, now time.Time, publicationID string) K8sStatusPayload {
	var checkStatus = make(map[string]*v1.CheckStatus)
	var messages, errorMsgs []string
	var failEvents []string
	var status v1.CanaryStatusCondition
	var lastTransitionedTime *metav1.Time
	var highestLatency float64
	var uptimeAgg dutyTypes.Uptime

	for _, result := range results {
		// Set uptime and latency
		uptime, latency := metrics.Record(ctx, canary, result)
		checkID := canary.Status.Checks[result.Check.GetName()]
		checkStatus[checkID] = &v1.CheckStatus{
			Uptime1H:  uptime.String(),
			Latency1H: latency.String(),
		}

		// Increment aggregate uptime
		uptimeAgg.Passed += uptime.Passed
		uptimeAgg.Failed += uptime.Failed

		// Use highest latency for canary status
		if latency.Rolling1H > highestLatency {
			highestLatency = latency.Rolling1H
		}

		transitioned := false
		latestCheckStatus, err := db.LatestCheckStatus(ctx, checkID, now)
		if err != nil || latestCheckStatus == nil {
			transitioned = true
		} else if latestCheckStatus.Status != result.Pass {
			transitioned = true
		}
		if transitioned {
			checkStatus[checkID].LastTransitionedTime = &metav1.Time{Time: now}
			lastTransitionedTime = &metav1.Time{Time: now}
		}

		if result.Message != "" {
			messages = append(messages, result.Message)
		}

		if result.Error != "" {
			errorMsgs = append(errorMsgs, result.Error)
		}

		if result.Pass {
			status = v1.Passed
		} else {
			failEvents = append(failEvents, fmt.Sprintf("%s-%s: %s", result.Check.GetType(), result.Check.GetEndpoint(), lo.CoalesceOrEmpty(result.Message, pkg.TruncateMessage(result.Error))))
			status = v1.Failed
		}

		if result.Invalid {
			status = v1.Invalid
		}
	}

	var errMsg string
	if len(errorMsgs) == 1 {
		errMsg = errorMsgs[0]
	} else if len(errorMsgs) > 1 {
		errMsg = fmt.Sprintf("%s, (%d more)", errorMsgs[0], len(errorMsgs)-1)
	}

	var msg string
	if len(messages) == 1 {
		msg = messages[0]
	} else if len(messages) > 1 {
		msg = fmt.Sprintf("%s, (%d more)", messages[0], len(messages)-1)
	}

	return K8sStatusPayload{
		Status:               status,
		CheckStatus:          checkStatus,
		FailEvents:           failEvents,
		LastTransitionedTime: lastTransitionedTime,
		Message:              msg,
		ErrorMessage:         errMsg,
		Uptime:               uptimeAgg.String(),
		Latency:              utils.Age(time.Duration(highestLatency) * time.Millisecond),
		NamespacedName:       canary.GetNamespacedName(),
		PublicationID:        publicationID,
	}
}
