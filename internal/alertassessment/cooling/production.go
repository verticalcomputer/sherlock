package cooling

import (
	"context"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// ProductionCategory shares the V1 evaluator and typed codecs while assigning
// an immutable implementation identity to the production-capable descriptor.
// Its validated REARM proof is a covered 300-second recovery interval. The
// production lifecycle records that proof as recovery; legacy replay is unchanged.
type ProductionCategory struct{ Category }

func (ProductionCategory) Describe() a.Descriptor {
	d := (Category{}).Describe()
	d.Implementation = 2
	d.Modes = []string{"production", "replay", "shadow"}
	return d
}

func (ProductionCategory) Evaluate(ctx context.Context, r a.Request) (a.Result, error) {
	if r.Implementation != 2 {
		return a.Result{}, a.ErrInvalid
	}
	r.Implementation = 1
	return (Category{}).Evaluate(ctx, r)
}
func (ProductionCategory) ValidateResult(ctx context.Context, r a.Request, x a.Result) error {
	if r.Implementation != 2 {
		return a.ErrInvalid
	}
	r.Implementation = 1
	return (Category{}).ValidateResult(ctx, r, x)
}
