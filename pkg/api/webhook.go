package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/flanksource/canary-checker/api/context"
	"github.com/flanksource/canary-checker/checks"
	"github.com/flanksource/canary-checker/pkg"
	"github.com/flanksource/canary-checker/pkg/cache"
	"github.com/flanksource/canary-checker/pkg/db"
	webhookdelivery "github.com/flanksource/canary-checker/pkg/webhook"
	"github.com/flanksource/duty/api"
	dutyContext "github.com/flanksource/duty/context"
	"github.com/labstack/echo/v4"
)

const webhookBodyLimit = 10 * 1024 // 10 MB

// CheckData is the parsed webhook payload. It is shared with the idempotent
// delivery package so transformation templates see the exact same value type
// on both the legacy and convergent paths.
type CheckData = webhookdelivery.Payload

func WebhookHandler(c echo.Context) error {
	id := c.Param("id")

	authToken := c.QueryParam("token")
	if authToken == "" {
		authToken = c.Request().Header.Get("Webhook-Token")
	}

	headers := make(map[string]string)
	for k := range c.Request().Header {
		headers[k] = c.Request().Header.Get(k)
	}

	// Restricted read: the raw payload is bounded regardless of content type.
	raw, err := io.ReadAll(io.LimitReader(c.Request().Body, webhookBodyLimit))
	if err != nil {
		return api.WriteError(c, err)
	}

	ctx := c.Request().Context().(dutyContext.Context)

	if c.Request().Header.Get("Content-Type") == "application/json" {
		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return api.WriteError(c, err)
		}

		err = webhookdelivery.Ingest(ctx, id, authToken, webhookdelivery.Payload{
			Headers: headers,
			JSON:    parsed,
		}, raw)
		if err != nil {
			return api.WriteError(c, err)
		}

		return c.JSON(http.StatusOK, &api.HTTPSuccess{Message: "ok"})
	}

	// Non-JSON payloads keep the legacy one-shot processing behavior.
	data := CheckData{Headers: headers, Content: string(raw)}
	if err := webhookHandlerLegacy(ctx, id, authToken, data); err != nil {
		return api.WriteError(c, err)
	}

	return c.JSON(http.StatusOK, &api.HTTPSuccess{Message: "ok"})
}

// webhookHandlerLegacy is the original one-shot conversion and persistence
// path, retained for payloads that do not participate in idempotent delivery
// (non-JSON bodies).
func webhookHandlerLegacy(ctx dutyContext.Context, id, authToken string, data CheckData) error {
	canaries, err := db.FindCanariesByWebhook(ctx, id)
	if err != nil {
		return err
	} else if len(canaries) == 0 {
		return api.Errorf(api.ENOTFOUND, "no canaries found for webhook: %s", id)
	} else if len(canaries) > 1 {
		return api.Errorf(api.EINVALID, "%d canaries were found for webhook: %s. please ensure that the webhook name is unique.", len(canaries), id)
	}

	canary, err := canaries[0].ToV1()
	if err != nil {
		return err
	}

	webhook := canary.Spec.Webhook

	// Authorization
	if webhook.Token != nil && !webhook.Token.IsEmpty() {
		token, err := ctx.GetEnvValueFromCache(*webhook.Token, canary.Namespace)
		if err != nil {
			return err
		}

		if token != "" && token != authToken {
			return api.Errorf(api.EUNAUTHORIZED, "invalid webhook token")
		}
	}

	result := pkg.Success(webhook, *canary)
	result.AddDetails(data)

	results := []*pkg.CheckResult{result}

	scrapeCtx := context.New(ctx, *canary)
	transformedResults := checks.TransformResults(scrapeCtx, results)

	checks.ExportCheckMetrics(scrapeCtx, transformedResults, true)
	for _, result := range transformedResults {
		_, err := cache.PostgresCache.Add(ctx, pkg.FromV1(result.Canary, result.Check), pkg.CheckStatusFromResult(*result))
		if err != nil {
			return err
		}
	}

	return nil
}
