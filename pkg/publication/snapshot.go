package publication

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/flanksource/canary-checker/api/external"
	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/pkg"
)

// buildSnapshot renders the live run into its persisted replay input.
func buildSnapshot(
	canary v1.Canary,
	results []*pkg.CheckResult,
	manifests []ArtifactManifest,
	allEvaluatedMetrics []pkg.Metric,
	harFilename string,
) (*Snapshot, error) {
	canaryJSON, err := json.Marshal(canary)
	if err != nil {
		return nil, fmt.Errorf("error marshalling canary snapshot: %w", err)
	}

	manifestsByCheck := make(map[string][]ArtifactManifest)
	for _, m := range manifests {
		manifestsByCheck[m.CheckID.String()] = append(manifestsByCheck[m.CheckID.String()], m)
	}

	snap := &Snapshot{Canary: canaryJSON, HARFilename: harFilename, EvaluatedMetrics: allEvaluatedMetrics}
	for _, result := range results {
		var detail json.RawMessage
		if result.Detail != nil {
			raw, err := json.Marshal(result.Detail)
			if err != nil {
				return nil, fmt.Errorf("error marshalling result detail: %w", err)
			}
			detail = raw
		}

		rs := ResultSnapshot{
			Name:           result.Check.GetName(),
			Type:           result.Check.GetType(),
			Description:    result.Check.GetDescription(),
			Endpoint:       canary.GetDescription(result.Check),
			Labels:         result.Check.GetLabels(),
			Transformed:    result.Transformed,
			Pass:           result.Pass,
			Invalid:        result.Invalid,
			InternalError:  result.InternalError,
			Duration:       result.Duration,
			Message:        result.Message,
			Error:          result.Error,
			Detail:         detail,
			Metrics:        result.Metrics,
			CanaryResult:   result.CanaryResult,
		}
		if rs.Labels == nil {
			rs.Labels = result.Labels
		}
		if result.ParentCheck != nil {
			rs.ParentName = result.ParentCheck.GetName()
			rs.ParentType = result.ParentCheck.GetType()
		}
		if checkID := result.Canary.GetCheckID(rs.Name); checkID != "" {
			rs.Artifacts = manifestsByCheck[checkID]
		}
		snap.Results = append(snap.Results, rs)
	}
	return snap, nil
}

// restore rebuilds the canary and check results captured by the snapshot
// without performing any external check.
func (s *Snapshot) restore(runTime time.Time) (*v1.Canary, []*pkg.CheckResult, error) {
	var canary v1.Canary
	if err := json.Unmarshal(s.Canary, &canary); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling canary snapshot: %w", err)
	}
	if canary.Namespace == "" {
		canary.Namespace = "default"
	}

	specChecks := make(map[string]external.Check)
	for _, check := range canary.Spec.GetAllChecks() {
		specChecks[check.GetType()+"|"+check.GetName()] = check
	}

	var results []*pkg.CheckResult
	for _, rs := range s.Results {
		r := &pkg.CheckResult{
			Start:         runTime,
			Pass:          rs.Pass,
			Invalid:       rs.Invalid,
			InternalError: rs.InternalError,
			Duration:      rs.Duration,
			Message:       rs.Message,
			Error:         rs.Error,
			Metrics:       rs.Metrics,
			Labels:        rs.Labels,
			Canary:        canary,
			CanaryResult:  rs.CanaryResult,
			Transformed:   rs.Transformed,
		}
		if len(rs.Detail) > 0 && string(rs.Detail) != "null" {
			r.Detail = rs.Detail
		}

		switch {
		case len(rs.CanaryResult) > 0:
			r.Check = genericCheck(rs)
		case rs.Transformed:
			r.Check = genericCheck(rs)
			if rs.ParentName != "" {
				if parent, ok := specChecks[rs.ParentType+"|"+rs.ParentName]; ok {
					r.ParentCheck = parent
				}
			}
		default:
			if check, ok := specChecks[rs.Type+"|"+rs.Name]; ok {
				r.Check = check
			} else {
				// The check spec is gone from the current canary spec; the
				// generic identity is enough to persist the captured result.
				r.Check = genericCheck(rs)
			}
		}

		results = append(results, r)
	}
	return &canary, results, nil
}

func genericCheck(rs ResultSnapshot) pkg.GenericCheck {
	labels := rs.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return pkg.GenericCheck{
		Description: v1.Description{
			Description: rs.Description,
			Name:        rs.Name,
			Labels:      labels,
		},
		Type:     rs.Type,
		Endpoint: rs.Endpoint,
	}
}
