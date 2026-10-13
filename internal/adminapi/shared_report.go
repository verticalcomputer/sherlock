package adminapi

import (
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"regexp"
)

func reportReadGrant(shared bool) humanRouteGrant {
	grant := humanRouteGrant{capability: auth.CapabilityInvestigationsRead}
	if !shared {
		grant.privilege = auth.PrivilegeRawEvidence
	}
	return grant
}

var sharedSecretAssignment = regexp.MustCompile(`(?i)["']?(?:password|sudo_password|ssh_password|secret|api_key|access_token|refresh_token|cookie)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`)

func sharedText(value string) string {
	return sharedSecretAssignment.ReplaceAllString(application.RedactSharedNarrative(value), "[REDACTED]")
}

// sharedReport retains the synthesized findings, durable progress and citation
// metadata. Raw scopes, model IO and context manifests never cross this boundary.
// Narrative receives the existing token redaction plus credential assignments;
// it is not a general-purpose DLP guarantee for arbitrary unlabeled text.
func sharedReport(report investigationReportDTO, version int) investigationReportDTO {
	report.Shared, report.Version = true, version
	report.ModelCalls = []modelCallDTO{}
	report.ContextManifests = []contextManifestDTO{}
	report.Question, report.StopReason = sharedText(report.Question), sharedText(report.StopReason)
	report.SuccessCriteria = append([]string{}, report.SuccessCriteria...)
	for i := range report.SuccessCriteria {
		report.SuccessCriteria[i] = sharedText(report.SuccessCriteria[i])
	}
	for i := range report.Findings {
		report.Findings[i].Statement = sharedText(report.Findings[i].Statement)
	}
	for i := range report.ReportSections {
		report.ReportSections[i].Statement = sharedText(report.ReportSections[i].Statement)
	}
	for i := range report.Evidence {
		report.Evidence[i].ExactScope = ""
	}
	if action := report.PrimaryAction; action != nil {
		action.Owner, action.Action, action.Rationale = sharedText(action.Owner), sharedText(action.Action), sharedText(action.Rationale)
		action.EscalationCondition = sharedText(action.EscalationCondition)
		for i := range action.BlockingGaps {
			action.BlockingGaps[i] = sharedText(action.BlockingGaps[i])
		}
	}
	return report
}
