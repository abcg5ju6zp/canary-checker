package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/flanksource/canary-checker/api/context"
	"github.com/flanksource/canary-checker/checks"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/cache"
	"github.com/flanksource/canary-checker/pkg/db"
	"github.com/flanksource/canary-checker/pkg/publication"
	pkgTopology "github.com/flanksource/canary-checker/pkg/topology"
	dutyContext "github.com/flanksource/duty/context"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type CheckErrorMessage struct {
	Description string `json:"description"`
	Error       string `json:"error"`
}

func RunCanaryHandler(c echo.Context) error {
	checkID := c.Param("id")
	duty := c.Request().Context().(dutyContext.Context)

	check, err := db.GetCheck(duty, checkID)
	if err != nil {
		return errorResponse(c, err, http.StatusInternalServerError)
	} else if check == nil {
		return errorResponse(c, fmt.Errorf("check (%s) was not found", checkID), http.StatusNotFound)
	}

	canaryModel, err := db.FindCanaryByID(duty, check.CanaryID.String())
	if err != nil {
		return errorResponse(c, err, http.StatusInternalServerError)
	} else if canaryModel == nil {
		return errorResponse(c, fmt.Errorf("canary (%s) was not found", check.CanaryID), http.StatusNotFound)
	}
	canary, err := canaryModel.ToV1()
	if err != nil {
		return errorResponse(c, err, http.StatusInternalServerError)
	}

	canary.Spec = canary.Spec.KeepOnly(check.Name)
	canary.Status.Checks = map[string]string{
		check.Name: check.ID.String(),
	}

	ctx := context.New(duty, *canary)

	if publication.ShouldGate(*canary, ctx.HARCollector != nil) {
		runKey := publication.RunNowRunKey(checkID, c.Request().Header.Get("Idempotency-Key"))
		outcome, err := publication.RunGated(duty, *canaryModel, *canary, runKey, publication.TriggerRunNow)
		if err != nil {
			return errorResponse(c, err, http.StatusInternalServerError)
		}
		if outcome == nil || outcome.Skipped {
			return errorResponse(c, fmt.Errorf("an identical run is already in progress"), http.StatusConflict)
		}
		if len(outcome.Results) == 0 {
			return nil
		}
		return c.JSON(http.StatusOK, outcome.Results[0])
	}

	results, _, err := checks.RunChecks(ctx)
	if err != nil {
		return errorResponse(c, err, http.StatusInternalServerError)
	}

	if len(results) == 0 {
		return nil
	}

	now := time.Now()

	for _, result := range results {
		if _, err := cache.PostgresCache.Add(ctx.Context, pkg.FromV1(result.Canary, result.Check), pkg.CheckStatusFromResult(*result)); err != nil {
			return errorResponse(c, err, http.StatusInternalServerError)
		}

		if err := publication.FormCheckRelationships(ctx.Context, result); err != nil {
			ctx.Logger.Named(result.Name).Errorf("error forming check relationships: %v", err)
		}
	}

	publication.PublishK8sStatusLegacy(ctx.Context, *canary, results, now)
	return c.JSON(http.StatusOK, results[0])
}

func RunTopologyHandler(c echo.Context) error {
	id := c.Param("id")

	ctx := c.Request().Context().(dutyContext.Context)
	topology, err := db.GetTopology(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errorResponse(c, fmt.Errorf("topology with id=%s was not found", id), http.StatusNotFound)
		}
		return errorResponse(c, err, http.StatusInternalServerError)
	}

	if components, history, err := pkgTopology.Run(ctx, *topology); err != nil {
		return errorResponse(c, err, http.StatusBadRequest)
	} else if history.AsError() != nil {
		return errorResponse(c, history.AsError(), http.StatusInternalServerError)
	} else {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok", "count": fmt.Sprintf("%d", len(components))})
	}
}
