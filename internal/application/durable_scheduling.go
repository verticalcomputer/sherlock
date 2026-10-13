package application

import (
	"context"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type DurableScheduleStore interface {
	AdmitDueSchedule(context.Context, domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error)
}

// AdmitDurableSchedule performs one globally fair turn. PostgreSQL owns the
// cursor, occurrence, quotas and executable queue; workers retain no due list.
func AdmitDurableSchedule(ctx context.Context, store DurableScheduleStore, policy domain.DurableAdmissionPolicy) (domain.ScheduleAdmission, bool, error) {
	if err := policy.Validate(); err != nil {
		return domain.ScheduleAdmission{}, false, err
	}
	return store.AdmitDueSchedule(ctx, policy)
}
