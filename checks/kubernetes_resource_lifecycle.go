package checks

import (
	gocontext "context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/samber/lo"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"

	"github.com/flanksource/canary-checker/api/context"
	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/is-healthy/pkg/health"
)

var (
	// runIDLabel identifies the single resource-check run that owns an
	// ephemeral object. Cleanup selectors are always scoped to the run id so
	// an old run can never delete objects claimed by a newer overlapping run.
	runIDLabel = resourceLabelKey("run-id")
	// specGenerationLabel pins the canary generation a run was started from.
	specGenerationLabel = resourceLabelKey("spec-generation")

	runStartedAtAnnotation = resourceLabelKey("run-started-at")
	runHeartbeatAnnotation = resourceLabelKey("run-heartbeat")
)

const (
	runHeartbeatInterval = 30 * time.Second
	// runHeartbeatTTL bounds how long after the last heartbeat (or run start)
	// another run considers a run group dead and allowed to reap it. It must be
	// several heartbeat intervals to tolerate transient API server failures.
	runHeartbeatTTL = 2 * time.Minute

	cleanupRetryAttempts = 2
	cleanupRetryInterval = 2 * time.Second
	cleanupPollInterval  = 2 * time.Second
)

// gvkDynamicClient is the subset of the kubernetes client used by the run
// lifecycle.
type gvkDynamicClient interface {
	GetClientByGroupVersionKind(ctx gocontext.Context, group, version, kind string) (dynamic.NamespaceableResourceInterface, error)
}

// resourceRun binds every phase of a single kubernetesResource run to one
// fixed identity: namespace completion, templating, apply confirmation,
// readiness observation, nested check results and cleanup progress all use the
// same run state and never cross into another run's objects.
type resourceRun struct {
	canaryID   string
	checkID    string
	runID      string
	generation int64
	startedAt  time.Time

	// finalized (namespace completed, owner referenced, templated & labelled)
	// manifests used by every subsequent phase.
	staticResources []unstructured.Unstructured
	resources       []unstructured.Unstructured

	// resources for which ownership by this run has been confirmed.
	appliedMu sync.Mutex
	applied   []unstructured.Unstructured

	// readiness observation and nested check output bound to this run.
	ready    map[string]health.HealthStatus
	observed map[string]map[string]any
	display  map[string]string

	heartbeatMu     sync.Mutex
	heartbeatCancel gocontext.CancelFunc
	heartbeatDone   chan struct{}
}

func newResourceRun(canary v1.Canary, checkName string) *resourceRun {
	return &resourceRun{
		canaryID:   canary.GetPersistedID(),
		checkID:    canary.GetCheckID(checkName),
		runID:      uuid.NewString(),
		generation: canary.Generation,
		startedAt:  time.Now().UTC(),
		display:    map[string]string{},
		observed:   map[string]map[string]any{},
	}
}

// detachContext returns a copy of the check context whose cancellation and
// deadline are detached while all values (logger, kubernetes connection, ...)
// are preserved. It allows run-scoped cleanup to finish after the run context
// is cancelled or hits its deadline (timeout, shutdown, cancellation).
func detachContext(ctx *context.Context) *context.Context {
	clone := *ctx
	dutyClone := ctx.Context
	commonsClone := dutyClone.Context
	commonsClone.Context = gocontext.WithoutCancel(commonsClone.Context)
	dutyClone.Context = commonsClone
	clone.Context = dutyClone
	return &clone
}

// identified reports whether the run has a durable identity (a persisted
// canary). Local runs from files without a persisted id keep the legacy
// canary/check label behaviour.
func (r *resourceRun) identified() bool {
	return r.canaryID != ""
}

func (r *resourceRun) startedAtString() string {
	return r.startedAt.Format(time.RFC3339)
}

func (r *resourceRun) markApplied(resource unstructured.Unstructured) {
	r.appliedMu.Lock()
	defer r.appliedMu.Unlock()
	r.applied = append(r.applied, resource)
}

// canaryCheckLabelSelector is the label selector shared by legacy cleanup and
// static resource cleanup: canary id (+ check id when known).
func canaryCheckLabelSelector(canaryID, checkID string) string {
	selector := fmt.Sprintf("%s=%s", resourceLabelKey("canary-id"), canaryID)
	if checkID != "" {
		selector += fmt.Sprintf(",%s=%s", resourceLabelKey("check-id"), checkID)
	}
	return selector
}

// ephemeralLabelSelector selects only ephemeral objects owned by this run.
func (r *resourceRun) ephemeralLabelSelector() string {
	selector := canaryCheckLabelSelector(r.canaryID, r.checkID)
	if r.identified() {
		selector += fmt.Sprintf(",%s=%s", runIDLabel, r.runID)
	}
	selector += fmt.Sprintf(",!%s", resourceLabelKey("is-static"))
	return selector
}

// orphanLabelSelector selects ephemeral objects of every run of the same
// canary/check; candidates for the fenced orphan sweep.
func (r *resourceRun) orphanLabelSelector() string {
	return canaryCheckLabelSelector(r.canaryID, r.checkID) + fmt.Sprintf(",!%s", resourceLabelKey("is-static"))
}

type resourceClient struct {
	client    dynamic.ResourceInterface
	group     string
	version   string
	kind      string
	namespace string
}

func resourceClientKey(group, version, kind, namespace string) string {
	return strings.Join([]string{group, version, kind, namespace}, "/")
}

// resourceClients builds a dynamic client per distinct group/version/kind AND
// namespace. Keying by the namespace as well is required so resources of the
// same GVK in different namespaces are each scoped correctly.
func resourceClients(ctx gocontext.Context, k8sClient gvkDynamicClient, resources []unstructured.Unstructured) (map[string]resourceClient, error) {
	clients := map[string]resourceClient{}
	for i := range resources {
		resource := resources[i]
		gvk := resource.GroupVersionKind()
		key := resourceClientKey(gvk.Group, gvk.Version, gvk.Kind, resource.GetNamespace())
		if _, ok := clients[key]; ok {
			continue
		}

		rc, err := k8sClient.GetClientByGroupVersionKind(ctx, gvk.Group, gvk.Version, gvk.Kind)
		if err != nil {
			return nil, fmt.Errorf("failed to get rest client for (%s/%s/%s): %w", gvk.Kind, resource.GetNamespace(), resource.GetName(), err)
		}

		clients[key] = resourceClient{
			client:    rc.Namespace(resource.GetNamespace()),
			group:     gvk.Group,
			version:   gvk.Version,
			kind:      gvk.Kind,
			namespace: resource.GetNamespace(),
		}
	}
	return clients, nil
}

// applyOwnership is the result of reconciling an uncertain apply response
// against the object's run identity.
type applyOwnership int

const (
	// applyOwned: the live object carries this run's identity.
	applyOwned applyOwnership = iota
	// applyMissing: no object exists, the apply genuinely failed.
	applyMissing
	// applyForeign: an object exists but it is owned by another (newer) run.
	applyForeign
)

// verifyAppliedObject reconciles an uncertain/erroring apply response by
// reading the object and matching this run's identity instead of blindly
// failing or re-applying.
func (r *resourceRun) verifyAppliedObject(ctx gocontext.Context, k8sClient gvkDynamicClient, resource unstructured.Unstructured) (applyOwnership, error) {
	gvk := resource.GroupVersionKind()
	rc, err := k8sClient.GetClientByGroupVersionKind(ctx, gvk.Group, gvk.Version, gvk.Kind)
	if err != nil {
		return applyMissing, err
	}

	live, err := rc.Namespace(resource.GetNamespace()).Get(ctx, resource.GetName(), metav1.GetOptions{})
	if err != nil {
		if apiErrors.IsNotFound(err) {
			return applyMissing, nil
		}
		return applyMissing, err
	}

	if !r.identified() {
		return applyOwned, nil
	}

	if live.GetLabels()[runIDLabel] == r.runID {
		return applyOwned, nil
	}
	return applyForeign, nil
}

// ownedByRun checks whether a live object observed during readiness wait
// belongs to this run.
func (r *resourceRun) ownedByRun(obj unstructured.Unstructured) bool {
	if !r.identified() {
		return true
	}
	return obj.GetLabels()[runIDLabel] == r.runID
}

// startHeartbeat periodically refreshes the run heartbeat annotation on the
// confirmed ephemeral objects. The heartbeat lets overlapping runs and
// post-restart runs distinguish a live run from a crashed one. It runs on a
// context detached from the check context so it keeps ticking while foreground
// deletion is being awaited on a cancelled run.
func (r *resourceRun) startHeartbeat(ctx gocontext.Context, k8sClient gvkDynamicClient) {
	if !r.identified() || len(r.resources) == 0 {
		return
	}

	r.heartbeatMu.Lock()
	defer r.heartbeatMu.Unlock()
	if r.heartbeatCancel != nil {
		return
	}

	hbCtx, cancel := gocontext.WithCancel(gocontext.WithoutCancel(ctx))
	done := make(chan struct{})
	r.heartbeatCancel = cancel
	r.heartbeatDone = done

	go func() {
		defer close(done)
		ticker := time.NewTicker(runHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				r.patchHeartbeat(hbCtx, k8sClient)
			}
		}
	}()
}

func (r *resourceRun) stopHeartbeat() {
	r.heartbeatMu.Lock()
	cancel, done := r.heartbeatCancel, r.heartbeatDone
	r.heartbeatCancel, r.heartbeatDone = nil, nil
	r.heartbeatMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (r *resourceRun) patchHeartbeat(ctx gocontext.Context, k8sClient gvkDynamicClient) {
	clients, err := resourceClients(ctx, k8sClient, r.resources)
	if err != nil {
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				runHeartbeatAnnotation: now,
			},
		},
	})
	if err != nil {
		return
	}

	for i := range r.resources {
		resource := r.resources[i]
		gvk := resource.GroupVersionKind()
		entry, ok := clients[resourceClientKey(gvk.Group, gvk.Version, gvk.Kind, resource.GetNamespace())]
		if !ok {
			continue
		}
		if _, err := entry.client.Patch(ctx, resource.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			if !apiErrors.IsNotFound(err) {
				// best effort: the next tick retries; sweep fencing tolerates
				// stale heartbeats up to runHeartbeatTTL.
				continue
			}
		}
	}
}

func deleteOptions(waitDelete bool) metav1.DeleteOptions {
	return metav1.DeleteOptions{
		GracePeriodSeconds: lo.ToPtr(int64(0)),
		PropagationPolicy:  lo.ToPtr(lo.Ternary(waitDelete, metav1.DeletePropagationForeground, metav1.DeletePropagationBackground)),
	}
}

func ignoreNotFound(err error) error {
	var statusErr *apiErrors.StatusError
	if errors.As(err, &statusErr) && statusErr.ErrStatus.Code == 404 {
		return nil
	}
	return err
}

// listOwned returns the live items of a group matching the run-scoped label
// selector.
func listOwned(ctx gocontext.Context, entry resourceClient, labelSelector string) ([]unstructured.Unstructured, error) {
	response, err := entry.client.List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		if apiErrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if response == nil {
		return nil, nil
	}
	return response.Items, nil
}

func deleteItems(ctx gocontext.Context, entry resourceClient, items []unstructured.Unstructured, waitDelete bool) error {
	var errs []error
	opts := deleteOptions(waitDelete)
	for i := range items {
		if err := ignoreNotFound(entry.client.Delete(ctx, items[i].GetName(), opts)); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete resource (%s/%s/%s): %w", entry.kind, entry.namespace, items[i].GetName(), err))
		}
	}
	return errors.Join(errs...)
}

// cleanup deletes every ephemeral object owned by this run. Every kind
// (including Namespace and Service) is first listed with the run-scoped label
// selector and only returned items are deleted by name, so an overlapping run
// that has re-claimed the same object names is never touched.
//
// Delete calls use ctx (detached from cancellation by the caller), while
// waitDone bounds the optional wait-for-delete polling so that opting into
// waitFor.delete keeps its existing cancellation behaviour. A confirmed check
// result is never overturned: remaining deletions are retried in place without
// re-running any external check, and leftovers are returned for later
// reaping by the orphan sweep.
func (r *resourceRun) cleanup(ctx *context.Context, waitDone gocontext.Context, waitDelete bool) error {
	if len(r.resources) == 0 {
		return nil
	}

	k8sClient, err := ctx.Kubernetes()
	if err != nil {
		return fmt.Errorf("error creating kubernetes client: %w", err)
	}

	selector := r.ephemeralLabelSelector()
	clients, err := resourceClients(ctx, k8sClient, r.resources)
	if err != nil {
		return err
	}

	var deleteErrs []error
	for attempt := 0; attempt <= cleanupRetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-waitDone.Done():
				return errors.Join(append(deleteErrs, waitDone.Err())...)
			case <-time.After(cleanupRetryInterval):
			}
		}

		deleteErrs = nil
		remaining := false
		for _, entry := range clients {
			items, err := listOwned(ctx, entry, selector)
			if err != nil {
				deleteErrs = append(deleteErrs, fmt.Errorf("error listing resource (%s/%s) for cleanup: %w", entry.kind, entry.namespace, err))
				remaining = true
				continue
			}
			if len(items) == 0 {
				continue
			}
			remaining = true
			if err := deleteItems(ctx, entry, items, waitDelete); err != nil {
				deleteErrs = append(deleteErrs, err)
			}
		}

		if !remaining {
			return nil
		}
		if len(deleteErrs) == 0 && !waitDelete {
			return nil
		}
		if len(deleteErrs) == 0 {
			break
		}
	}

	if !waitDelete {
		return errors.Join(deleteErrs...)
	}

	return r.waitForDeletion(ctx, waitDone, clients, selector, deleteErrs)
}

func (r *resourceRun) waitForDeletion(ctx *context.Context, waitDone gocontext.Context, clients map[string]resourceClient, selector string, deleteErrs []error) error {
	ticker := time.NewTicker(cleanupPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-waitDone.Done():
			return errors.Join(append(deleteErrs, waitDone.Err())...)
		case <-ticker.C:
			pending := map[string]resourceClient{}
			for key, entry := range clients {
				items, err := listOwned(ctx, entry, selector)
				if err != nil {
					deleteErrs = append(deleteErrs, fmt.Errorf("error getting resource (%s/%s) while polling: %w", entry.kind, entry.namespace, err))
					pending[key] = entry
					continue
				}
				if len(items) > 0 {
					ctx.Tracef("%d (%s/%s) resources have not been deleted", len(items), entry.kind, entry.namespace)
					pending[key] = entry
				} else {
					ctx.Tracef("all (%s/%s) have been deleted", entry.kind, entry.namespace)
				}
			}
			if len(pending) == 0 {
				ctx.Tracef("all the resources have been deleted")
				return nil
			}
			clients = pending
		}
	}
}

type orphanItem struct {
	entry  resourceClient
	object unstructured.Unstructured
}

// reapDecision decides whether a resource group belonging to another run can
// safely be reaped by this run. The group must be explicitly run labelled
// (never touch legacy/unlabelled objects or objects from a rollout of an older
// binary), belong to a different run, have started before this run (an old run
// can never reap a newer run) and be provably dead (no heartbeat within the
// TTL).
func reapDecision(run *resourceRun, groupRunID string, items []unstructured.Unstructured, now time.Time) bool {
	if groupRunID == "" || groupRunID == run.runID {
		return false
	}

	var startedAt, lastHeartbeat time.Time
	for i := range items {
		annotations := items[i].GetAnnotations()
		if value, ok := annotations[runStartedAtAnnotation]; ok {
			if t, err := time.Parse(time.RFC3339, value); err == nil && (startedAt.IsZero() || t.Before(startedAt)) {
				startedAt = t.UTC()
			}
		}
		if value, ok := annotations[runHeartbeatAnnotation]; ok {
			if t, err := time.Parse(time.RFC3339, value); err == nil && t.After(lastHeartbeat) {
				lastHeartbeat = t.UTC()
			}
		}
	}

	// Without a known start time the group cannot be fenced safely.
	if startedAt.IsZero() {
		return false
	}
	// A run that started at the same time or later is newer (or overlapping);
	// never delete its objects.
	if !startedAt.Before(run.startedAt) {
		return false
	}

	lastSeen := startedAt
	if lastHeartbeat.After(lastSeen) {
		lastSeen = lastHeartbeat
	}
	return now.Sub(lastSeen) > runHeartbeatTTL
}

// sweepOrphanedResources reclaims ephemeral objects left behind by runs that
// died between apply and cleanup (process exit, crash, cancellation without a
// draining cleanup). Only groups fenced as dead by reapDecision are deleted,
// so concurrent live runs and newer runs are never affected.
func (r *resourceRun) sweepOrphanedResources(ctx *context.Context) error {
	if !r.identified() || len(r.resources) == 0 {
		return nil
	}

	k8sClient, err := ctx.Kubernetes()
	if err != nil {
		return fmt.Errorf("error creating kubernetes client: %w", err)
	}

	clients, err := resourceClients(ctx, k8sClient, r.resources)
	if err != nil {
		return err
	}

	groups := map[string][]orphanItem{}
	seen := map[string]struct{}{}
	for _, entry := range clients {
		items, err := listOwned(ctx, entry, r.orphanLabelSelector())
		if err != nil {
			ctx.Tracef("failed to list orphan candidates for (%s/%s): %v", entry.kind, entry.namespace, err)
			continue
		}
		for i := range items {
			item := items[i]
			key := string(item.GetUID())
			if key == "" {
				key = fmt.Sprintf("%s/%s/%s/%s/%s", entry.group, entry.version, entry.kind, entry.namespace, item.GetName())
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			groupRunID := item.GetLabels()[runIDLabel]
			groups[groupRunID] = append(groups[groupRunID], orphanItem{entry: entry, object: item})
		}
	}

	var errs []error
	now := time.Now().UTC()
	for groupRunID, items := range groups {
		objects := lo.Map(items, func(item orphanItem, _ int) unstructured.Unstructured { return item.object })
		if !reapDecision(r, groupRunID, objects, now) {
			continue
		}
		ctx.Tracef("reaping %d orphaned resources of dead run %s", len(items), groupRunID)
		byClient := map[resourceClient][]unstructured.Unstructured{}
		for _, item := range items {
			byClient[item.entry] = append(byClient[item.entry], item.object)
		}
		for entry, objects := range byClient {
			if err := deleteItems(ctx, entry, objects, false); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// specGenerationLabelValue returns the pinned canary spec version label value.
func specGenerationLabelValue(generation int64) string {
	return strconv.FormatInt(generation, 10)
}
