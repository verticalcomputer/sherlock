package azureopenai

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

const warmingInstructions = `You triage a slow GPU warming alert for a hardware team. Decide NOTIFY now if the observed thermal behavior warrants hardware investigation, or WATCH and reassess in a minute. Weigh persistent or increasing heat against pre-event operating temperatures and changes in power and utilization. A utilization signal may be unavailable. Do not claim a physical diagnosis. No future observations are supplied. Return JSON with action (WATCH or NOTIFY) and a short reason. Times are seconds relative to the original alert. Rows are [time, Celsius, watts, percent utilization]; null means unavailable. Also use the supplied chronological plateau summaries. Each gives the first and last observed second and median values in the order of its named signals. Joint power/utilization plateaus require a 60s span within 25W and 5 percentage points; power-only plateaus cannot establish utilization; temperature plateaus require 45s within 1C. Missing samples can split a plateau. Compare the initial thermal response to a load step with subsequent temperature levels while that same load persists. A sustained second rise above a previously established loaded thermal plateau without another load increase warrants hardware investigation, even if temperature later levels off. A return to temperatures already seen under comparable load provides evidence for watching. Describe the temporal evidence supporting your decision.`

const warmingSchema = `{"type":"object","additionalProperties":false,"required":["action","reason"],"properties":{"action":{"type":"string","enum":["WATCH","NOTIFY"]},"reason":{"type":"string"}}}`

// TriageWarming evaluates a confirmed warming event using its time-bounded
// telemetry. It never publishes a notification or includes telemetry in logs.
func (provider *Provider) TriageWarming(ctx context.Context, evidence json.RawMessage) (action, reason string, err error) {
	payload := bytes.TrimSpace(evidence)
	if len(payload) == 0 || len(payload) > 64<<10 || payload[0] != '{' || !json.Valid(payload) {
		return "", "", &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	// Keep retries within the same wall-clock allowance as the initial call.
	ctx, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	result, err := provider.respond(ctx, "warming", warmingInstructions, payload, json.RawMessage(warmingSchema), min(provider.maxOutputTokens, 1200))
	if err != nil {
		return "", "", err
	}
	if result.refused {
		return "", "", &Error{Code: ErrorRefused, Stage: StageSemanticValidation}
	}
	action, reason, err = modelprovider.DecodeWarmingDecision(result.output)
	if err != nil {
		return "", "", structuredOutputError(err)
	}
	return action, reason, nil
}
