package checks

import (
	gocontext "context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flanksource/duty/connection"
	"github.com/flanksource/gomplate/v3"
	"github.com/flanksource/is-healthy/pkg/health"
	"github.com/flanksource/is-healthy/pkg/lua"
	"github.com/flanksource/kommons"
	"github.com/patrickmn/go-cache"
	"github.com/samber/lo"
	"github.com/sethvargo/go-retry"
	"golang.org/x/sync/errgroup"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/flanksource/canary-checker/api/context"
	"github.com/flanksource/canary-checker/api/external"
	v1 "github.com/flanksource/canary-checker/api/v1"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/commons/collections"
	"github.com/flanksource/commons/logger"
)

const (
	// maximum number of static & non static resources a canary can have
	defaultMaxResourcesAllowed = 10

	resourceWaitTimeoutDefault  = time.Minute * 10
	resourceWaitIntervalDefault = time.Second * 5
	waitForExprDefault          = `dyn(resources).all(r, k8s.isReady(r))`
)

func resourceLabelKey(key string) string {
	return fmt.Sprintf("canaries.flanksource.com/%s", key)
}

func getName(o unstructured.Unstructured) string {
	return fmt.Sprintf("%s/%s/%s", o.GetNamespace(), o.GetKind(), o.GetName())
}

type KubernetesResourceChecker struct{}

func (c *KubernetesResourceChecker) Type() string {
	return "kubernetes_resource"
}

// HandlesRetriesInternally keeps kubernetesResource retries scoped to
// embedded virtual checks instead of retrying the full resource lifecycle.
func (c *KubernetesResourceChecker) HandlesRetriesInternally() bool {
	return true
}

func (c *KubernetesResourceChecker) Run(ctx *context.Context) pkg.Results {
	var results pkg.Results
	for _, conf := range ctx.Canary.Spec.KubernetesResource {
		results = append(results, c.Check(ctx, conf)...)
	}
	return results
}

func (c *KubernetesResourceChecker) Check(ctx *context.Context, extConfig external.Check) pkg.Results {
	check := extConfig.(v1.KubernetesResourceCheck)
	return c.check(*ctx, *check.DeepCopy())
}

func (c *KubernetesResourceChecker) check(ctx context.Context, check v1.KubernetesResourceCheck) pkg.Results {
	result := pkg.Success(check, ctx.Canary)
	var results pkg.Results
	results = append(results, result)

	// We do this before virtual check run in case the check times out
	// and returns an err, the default templating requires 'display' in env
	result.AddData(map[string]any{
		"display": make(map[string]any),
	})

	if err := c.validate(ctx, check); err != nil {
		return results.Failf("validation: %v", err)
	}

	policy, err := newRetryPolicy(mergeCheckRetries(ctx.Canary.Spec.Retries, check.GetRetries()))
	if err != nil {
		return results.Failf("validation: retries: %v", err)
	}

	if check.Kubeconfig != nil {
		ctx = ctx.WithKubernetesConnection(connection.KubernetesConnection{
			KubeconfigConnection: connection.KubeconfigConnection{
				Kubeconfig: check.Kubeconfig,
			},
		})
	}

	// The run identity and pinned canary spec version are established before
	// namespace completion so every subsequent phase shares one lifecycle.
	run := newResourceRun(ctx.Canary, check.GetName())

	if check.HasResourcesWithMissingNamespace() {
		namespacedResources, err := fetchNamespacedResources(ctx)
		if err != nil {
			return results.Failf("failed to get api resources: %v", err)
		}

		check.SetMissingNamespace(ctx.Canary, namespacedResources)
	}

	check.SetCanaryOwnerReference(ctx.Canary)

	if err := templateKubernetesResourceCheck(run, &check); err != nil {
		return results.Failf("templating error: %v", err)
	}

	k8sClient, err := ctx.Kubernetes()
	if err != nil {
		return results.WithError(err).Invalidf("Cannot connect to kubernetes")
	}

	kClient := kommons.NewClient(k8sClient.RestConfig(), ctx.Logger)

	for i := range run.staticResources {
		resource := run.staticResources[i]
		if err := kClient.ApplyUnstructured(resource.GetNamespace(), &resource); err != nil {
			return results.Failf("failed to apply static resource %s: %v", resource.GetName(), err)
		}
	}

	defer func() {
		// Local runs without a persistent identity keep the legacy cleanup
		// behaviour exactly.
		if !run.identified() {
			if err := DeleteResources(ctx, check, false); err != nil {
				results.Failf("failed to delete resources: %s", err)
			}
			return
		}

		// Cleanup is scoped to this run's own objects and runs on a context
		// detached from cancellation/deadlines so timeout and cancellation still
		// complete this run's cleanup. A confirmed check result is retained:
		// cleanup continues best effort and never re-runs external checks;
		// leftovers are reclaimed by a later run's fenced orphan sweep.
		cleanupErr := run.cleanup(detachContext(&ctx), ctx, check.WaitFor.Delete)
		run.stopHeartbeat()
		if cleanupErr != nil {
			logger.Errorf("failed to delete resources for run %s: %v", run.runID, cleanupErr)
			if result.Pass {
				result.AddData(map[string]any{"cleanupError": cleanupErr.Error()})
			}
		}
	}()

	if run.identified() {
		if check.ClearResources {
			// Only this run's own temporary objects may be removed before
			// applying; overlapping runs are never affected.
			if err := run.cleanup(&ctx, ctx, false); err != nil {
				return results.Failf("failed to delete resources on startup: %s", err)
			}
		}

		// Reclaim objects left behind by crashed/cancelled runs, fenced by run
		// identity so live or newer runs are never touched.
		if err := run.sweepOrphanedResources(&ctx); err != nil {
			ctx.Tracef("failed to sweep orphaned resources: %v", err)
		}
	} else if check.ClearResources {
		if err := DeleteResources(ctx, check, false); err != nil {
			return results.Failf("failed to delete resources on startup: %s", err)
		}
	}

	for i := range run.resources {
		resource := run.resources[i]
		if err := kClient.ApplyUnstructured(resource.GetNamespace(), &resource); err != nil {
			if !run.identified() {
				return results.Failf("failed to apply resource (%s/%s/%s): %v", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
			}

			// The apply response is uncertain (e.g. timeout after the object
			// was persisted): reconcile against this run's object identity
			// instead of blindly failing or re-applying.
			ownership, verifyErr := run.verifyAppliedObject(ctx, k8sClient, resource)
			if verifyErr != nil {
				return results.Failf("failed to apply resource (%s/%s/%s): %v (identity verification failed: %v)", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err, verifyErr)
			}

			switch ownership {
			case applyOwned:
				ctx.Tracef("apply response for %s was uncertain but the object was confirmed for run %s", getName(resource), run.runID)
			case applyMissing:
				return results.Failf("failed to apply resource (%s/%s/%s): %v", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
			case applyForeign:
				return results.Failf("failed to apply resource (%s/%s/%s): an object exists but is owned by another overlapping run", resource.GetKind(), resource.GetNamespace(), resource.GetName())
			}
		}
		run.markApplied(resource)
	}

	run.startHeartbeat(ctx, k8sClient)

	if !check.WaitFor.Disable {
		var resourceObjs []unstructured.Unstructured
		if run.ready, resourceObjs, err = c.evalWaitFor(ctx, run, check); err != nil {
			return results.Failf("error in evaluating wait for: %v", err)
		}

		for _, r := range resourceObjs {
			r.SetManagedFields(nil)
			run.observed[getName(r)] = r.Object
		}
	}

	ctx.Tracef("found %d checks to run", len(check.Checks))
	for _, c := range check.Checks {
		virtualCanary := v1.Canary{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ctx.Canary.ObjectMeta.Name,
				Namespace: ctx.Canary.ObjectMeta.Namespace,
				Labels:    ctx.Canary.ObjectMeta.Labels,
			},
			Spec: c.CanarySpec,
		}

		templater := gomplate.StructTemplater{
			Values: map[string]any{
				"staticResources": run.staticResources,
				"resources":       run.resources,
			},
			ValueFunctions: true,
			IgnoreFields: map[string]string{
				"URL": "string", // Avoid templating URL which might have non-templated username, password etc.
			},
			DelimSets: []gomplate.Delims{
				{Left: "{{", Right: "}}"},
				{Left: "$(", Right: ")"},
			},
		}
		if err := templater.Walk(&virtualCanary); err != nil {
			return results.Failf("error templating checks: %v", err)
		}

		if !policy.disabled && policy.delay > 0 {
			if err := sleepWithContext(&ctx, policy.delay); err != nil {
				return results.ErrorMessage(err)
			}
		}

		start := time.Now()
		attempts := 0
		for {
			attempts++
			ctx.Tracef("running check: %s", virtualCanary.Name)

			checkCtx := context.New(ctx.Context, virtualCanary)
			res, err := RunChecksNoPersistence(checkCtx)
			var retryErr error
			if err != nil {
				retryErr = fmt.Errorf("error executing check: %w", err)
			} else {
				for _, r := range res {
					if !r.Pass {
						if r.Error != "" {
							retryErr = fmt.Errorf("check (name:%s) failed with error: %v", r.GetName(), r.Error)
						} else {
							retryErr = fmt.Errorf("check (name:%s) failed", r.GetName())
						}
						break
					}
				}
			}

			if retryErr == nil {
				for _, r := range res {
					run.display[r.Check.GetName()] = r.Message
				}
				break
			}

			if !policy.canRetry(attempts, start) {
				return results.ErrorMessage(retryErr)
			}
			if err := sleepWithContext(&ctx, policy.nextInterval(start)); err != nil {
				return results.ErrorMessage(err)
			}
		}
	}

	result.AddData(map[string]any{
		"health":    run.ready,
		"resources": run.observed,
		"display":   run.display,
	})
	return results
}

func (c *KubernetesResourceChecker) evalWaitFor(ctx context.Context, run *resourceRun, check v1.KubernetesResourceCheck) (map[string]health.HealthStatus, []unstructured.Unstructured, error) {
	healthMap := make(map[string]health.HealthStatus)
	waitTimeout, _ := check.WaitFor.Timeout.GetDurationOr(resourceWaitTimeoutDefault)
	waitInterval, _ := check.WaitFor.Interval.GetDurationOr(resourceWaitIntervalDefault)
	var resourceObjs []unstructured.Unstructured
	var err error
	var attempts int
	k8sClient, err := ctx.Kubernetes()
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kubernetes client: %w", err)
	}
	backoff := retry.WithMaxDuration(waitTimeout, retry.NewConstant(waitInterval))
	retryErr := retry.Do(ctx, backoff, func(_ctx gocontext.Context) error {
		ctx = _ctx.(context.Context)
		attempts++

		ctx.Tracef("waiting for %d resources, attempt=%d, timeout=%s", check.TotalResources(), attempts, waitTimeout)

		resourceObjs, err = k8sClient.FetchResources(ctx, append(check.StaticResources, check.Resources...)...)
		if err != nil {
			if apiErrors.IsNotFound(err) {
				return retry.RetryableError(err)
			}

			return fmt.Errorf("wait for evaluation. fetching resources: %w", err)
		} else if len(resourceObjs) != check.TotalResources() {
			var got []string
			for _, r := range resourceObjs {
				got = append(got, fmt.Sprintf("%s/%s/%s", r.GetKind(), r.GetNamespace(), r.GetName()))
			}

			return fmt.Errorf("unexpected error. expected %d resources, got %d (%s)", check.TotalResources(), len(resourceObjs), strings.Join(got, ","))
		}

		// Every observed ephemeral object must still carry this run's
		// identity. An overlapping run that has re-applied the same object
		// names re-labels them; waiting on or checking another run's objects
		// would be unsafe, so stop without retrying.
		for i := range resourceObjs {
			r := &resourceObjs[i]
			if r.GetLabels()[resourceLabelKey("is-static")] == "true" {
				continue
			}
			if !run.ownedByRun(*r) {
				owner := r.GetLabels()[runIDLabel]
				return fmt.Errorf("resource %s is owned by another run (%s), aborting to avoid interfering with an overlapping run", getName(*r), owner)
			}
		}

		waitForExpr := check.WaitFor.Expr
		if waitForExpr == "" {
			waitForExpr = waitForExprDefault
		}

		var templateVar = map[string]any{
			"resources": resourceObjs,
		}
		if response, err := gomplate.RunTemplate(templateVar, gomplate.Template{Expression: waitForExpr}); err != nil {
			return fmt.Errorf("wait for expression evaluation: %w", err)
		} else if passed, err := strconv.ParseBool(response); err != nil {
			return fmt.Errorf("wait for expression (%q) didn't evaluate to a boolean", check.WaitFor.Expr)
		} else {
			notReadyResources := []string{}
			for _, r := range resourceObjs {
				rh, _ := health.GetResourceHealth(&r, lua.ResourceHealthOverrides{})
				name := getName(r)
				healthMap[name] = *rh
				ctx.Tracef("health for %s: %s ready=%v", name, rh, rh.Ready)
				if rh.Health.IsWorseThan(health.HealthWarning) {
					notReadyResources = append(notReadyResources, fmt.Sprintf("%s: %s", name, rh))
				} else if !rh.Ready {
					notReadyResources = append(notReadyResources, fmt.Sprintf("%s: not ready", name))
				}
			}
			if passed {
				return nil
			}
			return retry.RetryableError(fmt.Errorf("%s", strings.Join(notReadyResources, ", ")))
		}
	})

	return healthMap, resourceObjs, retryErr
}

func (c *KubernetesResourceChecker) validate(ctx context.Context, check v1.KubernetesResourceCheck) error {
	if err := check.WaitFor.Timeout.Validate(); err != nil {
		return fmt.Errorf("waitFor.timeout: %s", err)
	}

	if err := check.WaitFor.Interval.Validate(); err != nil {
		return fmt.Errorf("waitFor.interval: %s", err)
	}

	retries := check.GetRetries()
	if _, err := retries.GetTimeout(); err != nil {
		return fmt.Errorf("timeout: %s", err)
	}

	if _, err := retries.GetInterval(); err != nil {
		return fmt.Errorf("interval: %s", err)
	}

	if _, err := retries.GetDelay(); err != nil {
		return fmt.Errorf("delay: %s", err)
	}

	maxResourcesAllowed := ctx.Properties().Int("checks.kubernetesResource.maxResources", defaultMaxResourcesAllowed)
	if check.TotalResources() > maxResourcesAllowed {
		return fmt.Errorf("too many resources (%d). only %d supported", check.TotalResources(), maxResourcesAllowed)
	}

	return nil
}

func DeleteResources(ctx context.Context, check v1.KubernetesResourceCheck, deleteStatic bool) error {
	ctx.Tracef("deleting resources")

	resources := check.Resources
	if deleteStatic {
		resources = append(resources, check.StaticResources...)
	}
	k8sClient, err := ctx.Kubernetes()
	if err != nil {
		return fmt.Errorf("error creating kubernetes client: %w", err)
	}

	// firstly, cache dynamic clients by gvk
	clients := sync.Map{}
	for i := range resources {
		resource := resources[i]

		gvk := resource.GetObjectKind().GroupVersionKind()
		if _, ok := clients.Load(gvk); ok {
			continue // client already cached
		}

		rc, err := k8sClient.GetClientByGroupVersionKind(ctx, resource.GroupVersionKind().Group, resource.GroupVersionKind().Version, resource.GetKind())
		if err != nil {
			return fmt.Errorf("failed to get rest client for (%s/%s/%s): %w", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
		}

		clients.Store(gvk, rc.Namespace(resource.GetNamespace()))
	}

	eg, _ := errgroup.WithContext(ctx)
	for i := range resources {
		resource := resources[i]

		eg.Go(func() error {
			cachedClient, _ := clients.Load(resource.GetObjectKind().GroupVersionKind())
			rc := cachedClient.(dynamic.NamespaceableResourceInterface)

			deleteOpt := metav1.DeleteOptions{
				GracePeriodSeconds: lo.ToPtr(int64(0)),
				PropagationPolicy:  lo.ToPtr(lo.Ternary(check.WaitFor.Delete, metav1.DeletePropagationForeground, metav1.DeletePropagationBackground)),
			}

			switch resource.GetKind() {
			case "Namespace", "Service":
				// NOTE: namespace cannot be deleted with `.DeleteCollection()`
				//
				// FIXME: Even though Service can be deleted with `.DeleteCollection()`
				// it failed on the CI. It's probably due to an older kubernetes
				// version we're using on the CI (v1.20.7).
				// Delete it by name for now while we wait upgrade the kubernetes version
				// on our CI.
				if err := rc.Delete(ctx, resource.GetName(), deleteOpt); err != nil {
					var statusErr *apiErrors.StatusError
					if errors.As(err, &statusErr) {
						switch statusErr.ErrStatus.Code {
						case 404:
							return nil
						}
					}

					return fmt.Errorf("failed to delete resource (%s/%s/%s): %w", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
				}

			default:
				labelSelector := fmt.Sprintf("%s=%s", resourceLabelKey("canary-id"), ctx.Canary.GetPersistedID())
				if checkID := ctx.Canary.GetCheckID(check.GetName()); checkID != "" {
					labelSelector += fmt.Sprintf(",%s=%s", resourceLabelKey("check-id"), checkID)
				}
				if !deleteStatic {
					labelSelector += fmt.Sprintf(",!%s", resourceLabelKey("is-static"))
				}

				if err := rc.DeleteCollection(ctx, deleteOpt, metav1.ListOptions{LabelSelector: labelSelector}); err != nil {
					var statusErr *apiErrors.StatusError
					if errors.As(err, &statusErr) {
						switch statusErr.ErrStatus.Code {
						case 404:
							return nil
						}
					}

					return fmt.Errorf("failed to delete resource (%s/%s/%s): %w", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
				}
			}

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	if !check.WaitFor.Delete {
		return nil
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if len(resources) == 0 {
				ctx.Tracef("all the resources have been deleted")
				return nil
			}

			deleted := make(map[schema.GroupVersionKind]struct{})
			for _, resource := range resources {
				gvk := resource.GetObjectKind().GroupVersionKind()
				cachedClient, _ := clients.Load(gvk)
				rc := cachedClient.(dynamic.ResourceInterface)

				labelSelector := fmt.Sprintf("%s=%s", resourceLabelKey("canary-id"), ctx.Canary.GetPersistedID())
				if checkID := ctx.Canary.GetCheckID(check.GetName()); checkID != "" {
					labelSelector += fmt.Sprintf(",%s=%s", resourceLabelKey("check-id"), checkID)
				}
				if !deleteStatic {
					labelSelector += fmt.Sprintf(",!%s", resourceLabelKey("is-static"))
				}

				if listResponse, err := rc.List(ctx, metav1.ListOptions{LabelSelector: labelSelector}); err != nil {
					return fmt.Errorf("error getting resource (%s/%s/%s) while polling: %w", resource.GetKind(), resource.GetNamespace(), resource.GetName(), err)
				} else if listResponse == nil || len(listResponse.Items) == 0 {
					ctx.Tracef("all (%v) have been deleted", gvk)
					deleted[gvk] = struct{}{}
				} else {
					ctx.Tracef("all (%v) have not been deleted", gvk)
				}
			}

			resources = lo.Filter(resources, func(item unstructured.Unstructured, _ int) bool {
				_, ok := deleted[item.GetObjectKind().GroupVersionKind()]
				return !ok
			})

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func templateKubernetesResourceCheck(run *resourceRun, check *v1.KubernetesResourceCheck) error {
	templater := gomplate.StructTemplater{
		ValueFunctions: true,
		DelimSets: []gomplate.Delims{
			{Left: "{{", Right: "}}"},
			{Left: "$(", Right: ")"},
		},
	}

	runLabels := map[string]string{
		resourceLabelKey("canary-id"): run.canaryID,
		resourceLabelKey("check-id"):  run.checkID,
	}
	if run.identified() {
		runLabels[runIDLabel] = run.runID
		if run.generation > 0 {
			runLabels[specGenerationLabel] = specGenerationLabelValue(run.generation)
		}
	}

	runAnnotations := map[string]string{}
	if run.identified() {
		runAnnotations[runStartedAtAnnotation] = run.startedAtString()
		runAnnotations[runHeartbeatAnnotation] = run.startedAtString()
	}

	for i, r := range check.Resources {
		namespace, kind := r.GetNamespace(), r.GetObjectKind().GroupVersionKind()
		if err := templater.Walk(&r); err != nil {
			return fmt.Errorf("error templating resource: %w", err)
		}

		if r.GetNamespace() != namespace || r.GetObjectKind().GroupVersionKind() != kind {
			return fmt.Errorf("templating the namespace or group/version/kind of a resource is not allowed")
		}
		r.SetLabels(collections.MergeMap(r.GetLabels(), runLabels))
		if run.identified() {
			r.SetAnnotations(collections.MergeMap(r.GetAnnotations(), runAnnotations))
		}
		check.Resources[i] = r
	}

	for i, r := range check.StaticResources {
		namespace, kind := r.GetNamespace(), r.GetKind()
		if err := templater.Walk(&r); err != nil {
			return fmt.Errorf("error templating resource: %w", err)
		}

		if r.GetNamespace() != namespace || r.GetKind() != kind {
			return fmt.Errorf("templating the namespace or group/version/kind of a resource is not allowed")
		}

		// Static resources are shared across runs and only deleted with the
		// canary, so they never carry run identity labels or heartbeats.
		staticLabels := map[string]string{
			resourceLabelKey("canary-id"): run.canaryID,
			resourceLabelKey("check-id"):  run.checkID,
			resourceLabelKey("is-static"): "true",
		}
		r.SetLabels(collections.MergeMap(r.GetLabels(), staticLabels))
		check.StaticResources[i] = r
	}

	run.resources = check.Resources
	run.staticResources = check.StaticResources

	return nil
}

var apiResourceCache = cache.New(time.Hour*24, time.Hour*24)

func fetchNamespacedResources(ctx context.Context) (map[schema.GroupVersionKind]bool, error) {
	kubeconfigCacheKey := ctx.KubeAuthFingerprint()
	if val, ok := apiResourceCache.Get(kubeconfigCacheKey); ok {
		return val.(map[schema.GroupVersionKind]bool), nil
	}

	k8sClient, err := ctx.Kubernetes()
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %w", err)
	}
	_, resourceList, err := k8sClient.Discovery().ServerGroupsAndResources()
	if err != nil {
		return nil, fmt.Errorf("failed to get server groups & resources: %w", err)
	}

	namespaceResources := make(map[schema.GroupVersionKind]bool)
	for _, apiResourceList := range resourceList {
		for _, resource := range apiResourceList.APIResources {
			if resource.Namespaced {
				gv, _ := schema.ParseGroupVersion(apiResourceList.GroupVersion)
				key := schema.GroupVersionKind{
					Group:   gv.Group,
					Version: gv.Version,
					Kind:    resource.Kind,
				}

				namespaceResources[key] = true
			}
		}
	}

	apiResourceCache.SetDefault(kubeconfigCacheKey, namespaceResources)
	return namespaceResources, nil
}
