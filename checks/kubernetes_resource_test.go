package checks

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/flanksource/canary-checker/api/v1"
)

func testResource(kind, namespace, name string, extraLabels map[string]string) unstructured.Unstructured {
	labels := map[string]any{"app": "test"}
	for k, v := range extraLabels {
		labels[k] = v
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels":    labels,
		},
	}}
}

func testCheck() v1.KubernetesResourceCheck {
	return v1.KubernetesResourceCheck{
		Description: v1.Description{Name: "kr-check"},
		Resources: []unstructured.Unstructured{
			testResource("Pod", "default", "tmp-pod", nil),
		},
		StaticResources: []unstructured.Unstructured{
			testResource("ConfigMap", "default", "shared-cm", nil),
		},
	}
}

func identifiedTestCanary() v1.Canary {
	return v1.Canary{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "canary",
			Namespace:  "default",
			UID:        types.UID("canary-uid"),
			Generation: 3,
		},
		Status: v1.CanaryStatus{Checks: map[string]string{"kr-check": "check-uuid"}},
	}
}

func TestTemplateStampsRunIdentityOnEphemeralResourcesOnly(t *testing.T) {
	canary := identifiedTestCanary()
	run := newResourceRun(canary, "kr-check")
	check := testCheck()

	if !run.identified() {
		t.Fatalf("expected run to be identified")
	}
	if run.runID == "" {
		t.Fatalf("expected a run id")
	}

	if err := templateKubernetesResourceCheck(run, &check); err != nil {
		t.Fatalf("templating failed: %v", err)
	}

	ephemeral := check.Resources[0]
	if got := ephemeral.GetLabels()[resourceLabelKey("canary-id")]; got != "canary-uid" {
		t.Fatalf("expected canary-id label, got %q", got)
	}
	if got := ephemeral.GetLabels()[resourceLabelKey("check-id")]; got != "check-uuid" {
		t.Fatalf("expected check-id label, got %q", got)
	}
	if got := ephemeral.GetLabels()[runIDLabel]; got != run.runID {
		t.Fatalf("expected run-id label %q, got %q", run.runID, got)
	}
	if got := ephemeral.GetLabels()[specGenerationLabel]; got != "3" {
		t.Fatalf("expected pinned spec generation label 3, got %q", got)
	}
	if got := ephemeral.GetAnnotations()[runStartedAtAnnotation]; got == "" {
		t.Fatalf("expected run started-at annotation")
	}
	if got := ephemeral.GetAnnotations()[runHeartbeatAnnotation]; got == "" {
		t.Fatalf("expected initial heartbeat annotation")
	}

	static := check.StaticResources[0]
	if got := static.GetLabels()[resourceLabelKey("is-static")]; got != "true" {
		t.Fatalf("expected is-static label, got %q", got)
	}
	if got := static.GetLabels()[runIDLabel]; got != "" {
		t.Fatalf("static resources must not carry run identity, got run-id %q", got)
	}
	if got := static.GetLabels()[specGenerationLabel]; got != "" {
		t.Fatalf("static resources must not carry spec generation, got %q", got)
	}
	if got := static.GetAnnotations()[runHeartbeatAnnotation]; got != "" {
		t.Fatalf("static resources must not carry heartbeat annotations")
	}

	if got := run.ephemeralLabelSelector(); got != "canaries.flanksource.com/canary-id=canary-uid,canaries.flanksource.com/check-id=check-uuid,"+
		"canaries.flanksource.com/run-id="+run.runID+",!canaries.flanksource.com/is-static" {
		t.Fatalf("unexpected run scoped selector: %q", got)
	}
}

func TestTemplateLocalRunKeepsLegacyLabels(t *testing.T) {
	canary := v1.Canary{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "default"}}
	run := newResourceRun(canary, "kr-check")
	check := testCheck()

	if run.identified() {
		t.Fatalf("local runs without a persisted id must not be identified")
	}
	if err := templateKubernetesResourceCheck(run, &check); err != nil {
		t.Fatalf("templating failed: %v", err)
	}

	ephemeral := check.Resources[0]
	if got := ephemeral.GetLabels()[runIDLabel]; got != "" {
		t.Fatalf("local runs must not stamp run-id, got %q", got)
	}
	if got := ephemeral.GetAnnotations()[runStartedAtAnnotation]; got != "" {
		t.Fatalf("local runs must not stamp run annotations")
	}
	if got := run.ephemeralLabelSelector(); got != "canaries.flanksource.com/canary-id=,!canaries.flanksource.com/is-static" {
		t.Fatalf("legacy selector changed, got %q", got)
	}
}

func labelledItem(runID string, startedAt, heartbeat *time.Time) unstructured.Unstructured {
	labels := map[string]any{"app": "test"}
	if runID != "" {
		labels[runIDLabel] = runID
	}
	annotations := map[string]any{}
	if startedAt != nil {
		annotations[runStartedAtAnnotation] = startedAt.Format(time.RFC3339)
	}
	if heartbeat != nil {
		annotations[runHeartbeatAnnotation] = heartbeat.Format(time.RFC3339)
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":        "tmp",
			"namespace":   "default",
			"labels":      labels,
			"annotations": annotations,
		},
	}}
}

func TestReapDecisionFencesByAgeAndHeartbeat(t *testing.T) {
	run := newResourceRun(identifiedTestCanary(), "kr-check")
	now := time.Now().UTC()

	older := now.Add(-10 * time.Minute)
	newer := now.Add(-1 * time.Minute)
	stale := now.Add(-runHeartbeatTTL - time.Minute)
	fresh := now.Add(-30 * time.Second)

	cases := []struct {
		name      string
		groupRun  string
		startedAt *time.Time
		heartbeat *time.Time
		want      bool
	}{
		{"dead older run is reaped", "dead-run", &older, &stale, true},
		{"crashed run without heartbeats is reaped after ttl", "crashed-run", &older, nil, true},
		{"live overlapping run is kept", "live-run", &older, &fresh, false},
		{"newer run is never reaped", "new-run", &newer, &fresh, false},
		{"newer run without heartbeat is never reaped", "new-run", &newer, nil, false},
		{"unlabelled legacy objects are kept", "", &older, &stale, false},
		{"objects without run annotations are kept", "mystery-run", nil, nil, false},
		{"self group is kept", run.runID, &older, &stale, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items := []unstructured.Unstructured{labelledItem(tc.groupRun, tc.startedAt, tc.heartbeat)}
			if got := reapDecision(run, tc.groupRun, items, now); got != tc.want {
				t.Fatalf("reapDecision() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOwnedByRun(t *testing.T) {
	run := newResourceRun(identifiedTestCanary(), "kr-check")

	owned := testResource("Pod", "default", "p", map[string]string{runIDLabel: run.runID})
	foreign := testResource("Pod", "default", "p", map[string]string{runIDLabel: "another-run"})
	unlabelled := testResource("Pod", "default", "p", nil)

	if !run.ownedByRun(owned) {
		t.Fatalf("object with this run id must be owned")
	}
	if run.ownedByRun(foreign) {
		t.Fatalf("object owned by another run must not be claimed")
	}
	if run.ownedByRun(unlabelled) {
		t.Fatalf("unlabelled object must not be claimed by an identified run")
	}

	localRun := newResourceRun(v1.Canary{ObjectMeta: metav1.ObjectMeta{Name: "local"}}, "kr-check")
	if !localRun.ownedByRun(unlabelled) {
		t.Fatalf("legacy local runs keep non-identity behaviour")
	}
}

func TestOrphanSelectorCoversEveryRunWithoutRunID(t *testing.T) {
	run := newResourceRun(identifiedTestCanary(), "kr-check")
	selector := run.orphanLabelSelector()
	want := "canaries.flanksource.com/canary-id=canary-uid,canaries.flanksource.com/check-id=check-uuid,!canaries.flanksource.com/is-static"
	if selector != want {
		t.Fatalf("orphan selector = %q, want %q", selector, want)
	}
}
