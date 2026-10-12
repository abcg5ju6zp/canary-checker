package webhook

import (
	"sync"
	"time"

	dutyContext "github.com/flanksource/duty/context"
	"github.com/flanksource/duty/types"
	"github.com/google/uuid"
)

// Receipt statuses.
const (
	StatusReceived  = "received"
	StatusPublished = "published"
	StatusConfirmed = "confirmed"
)

const (
	receiptsTable = "webhook_event_receipts"
	checksTable   = "webhook_event_checks"
)

var ensureSchemaOnce sync.Once
var ensureSchemaErr error

// EnsureSchema creates the idempotency tables used to converge redelivered
// webhook batches. It is safe to call concurrently from multiple instances.
func EnsureSchema(ctx dutyContext.Context) error {
	ensureSchemaOnce.Do(func() {
		ensureSchemaErr = ctx.DB().Exec(schemaSQL).Error
	})
	return ensureSchemaErr
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS webhook_event_receipts (
    event_id          TEXT PRIMARY KEY,
    webhook_name      TEXT NOT NULL,
    canary_id         UUID NOT NULL,
    raw_payload       JSONB,
    headers           JSONB,
    spec_snapshot     JSONB NOT NULL,
    canary_meta       JSONB NOT NULL,
    config_generation TEXT NOT NULL,
    auth_token_hash   TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL,
    checks            JSONB NOT NULL DEFAULT '[]',
    error             TEXT,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at      TIMESTAMPTZ,
    confirmed_at      TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhook_event_checks (
    event_id          TEXT NOT NULL REFERENCES webhook_event_receipts(event_id) ON DELETE CASCADE,
    ordinal           INT NOT NULL,
    check_key         TEXT NOT NULL,
    check_id          UUID,
    source_event_time TIMESTAMPTZ NOT NULL,
    status_time       TIMESTAMPTZ NOT NULL,
    resolved          BOOLEAN NOT NULL DEFAULT FALSE,
    published         BOOLEAN NOT NULL DEFAULT FALSE,
    skipped_stale     BOOLEAN NOT NULL DEFAULT FALSE,
    metrics_exported  BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (event_id, check_key)
);

CREATE INDEX IF NOT EXISTS idx_webhook_event_checks_watermark
    ON webhook_event_checks (check_key, source_event_time);
CREATE INDEX IF NOT EXISTS idx_webhook_event_receipts_status
    ON webhook_event_receipts (status, received_at);
`

// receipt binds everything belonging to a single delivery: the raw payload,
// the config generation (and credential) used for authorization, the set of
// checks the payload converted into, and the processing outcome.
type receipt struct {
	EventID          string                `gorm:"column:event_id;primaryKey"`
	WebhookName      string                `gorm:"column:webhook_name"`
	CanaryID         uuid.UUID             `gorm:"column:canary_id"`
	RawPayload       types.JSON            `gorm:"column:raw_payload"`
	Headers          types.JSONStringMap   `gorm:"column:headers"`
	SpecSnapshot     types.JSON            `gorm:"column:spec_snapshot"`
	CanaryMeta       types.JSON            `gorm:"column:canary_meta"`
	ConfigGeneration string                `gorm:"column:config_generation"`
	AuthTokenHash    string                `gorm:"column:auth_token_hash"`
	Status           string                `gorm:"column:status"`
	Checks           types.JSON            `gorm:"column:checks"`
	Error            string                `gorm:"column:error"`
	ReceivedAt       time.Time             `gorm:"column:received_at"`
	PublishedAt      *time.Time            `gorm:"column:published_at"`
	ConfirmedAt      *time.Time            `gorm:"column:confirmed_at"`
	UpdatedAt        time.Time             `gorm:"column:updated_at"`
}

func (receipt) TableName() string { return receiptsTable }

// eventCheckRow tracks the publication state of a single check within a
// delivered event, allowing batches to resume from never-confirmed checks.
type eventCheckRow struct {
	EventID         string     `gorm:"column:event_id;primaryKey"`
	Ordinal         int        `gorm:"column:ordinal"`
	CheckKey        string     `gorm:"column:check_key;primaryKey"`
	CheckID         *uuid.UUID `gorm:"column:check_id"`
	SourceEventTime time.Time  `gorm:"column:source_event_time"`
	StatusTime      time.Time  `gorm:"column:status_time"`
	Resolved        bool       `gorm:"column:resolved"`
	Published       bool       `gorm:"column:published"`
	SkippedStale    bool       `gorm:"column:skipped_stale"`
	MetricsExported bool       `gorm:"column:metrics_exported"`
}

func (eventCheckRow) TableName() string { return checksTable }

// plannedCheck is the JSONB snapshot of a converted check, persisted with the
// receipt so the conversion result remains auditable after the event.
type plannedCheck struct {
	Ordinal         int       `json:"ordinal"`
	CheckKey        string    `json:"check_key"`
	Type            string    `json:"type"`
	Name            string    `json:"name"`
	SourceEventTime time.Time `json:"source_event_time"`
	StatusTime      time.Time `json:"status_time"`
	Resolved        bool      `json:"resolved"`
}

type canaryMeta struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
