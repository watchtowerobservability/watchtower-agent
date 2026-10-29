package custom

import (
	"io"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// parseProm parses Prometheus text exposition (TextToMetricFamilies has a pointer receiver).
func parseProm(r io.Reader) (map[string]*dto.MetricFamily, error) {
	p := expfmt.NewTextParser(model.UTF8Validation)
	return p.TextToMetricFamilies(r)
}
