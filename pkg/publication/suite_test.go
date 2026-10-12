package publication

import (
	"testing"

	"github.com/flanksource/canary-checker/pkg/cache"
	dutyContext "github.com/flanksource/duty/context"
	"github.com/flanksource/duty/tests/setup"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var DefaultContext dutyContext.Context

func TestPublication(t *testing.T) {
	RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Check run publications")
}

var _ = ginkgo.BeforeSuite(func() {
	DefaultContext = setup.BeforeSuiteFn().WithTrace()
	cache.PostgresCache = cache.NewPostgresCache(DefaultContext)
})

var _ = ginkgo.AfterSuite(func() {
	setup.AfterSuiteFn()
})
