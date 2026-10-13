package diagnosticrunner

import (
	"context"
	"errors"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

// ErrForeignTarget means an invocation asked this host to answer for a machine
// that is not this host.
var ErrForeignTarget = errors.New("host invoker: invocation targets another machine")

// HostInvoker executes a verified invocation on the machine it runs on, with no
// SSH hop. It is the second LocalInvoker beside RestrictedSSH, and it exists
// for the case where the head node is itself the target: a single-node
// development cluster, or a HEAD-role definition answering about the head node.
//
// It refuses any invocation whose target set is not exactly this host, and that
// refusal is the reason the type is safe to have at all. Runner.ExecuteVerified
// runs the plan's argv once per target on the local machine and labels each run
// with that target's name. Handing it comp001..comp008 from one host would
// therefore run one local command eight times and record eight per-target
// results, and those results become immutable evidence envelopes that an
// investigation cites. That is not a degraded probe; it is fabricated evidence
// for seven machines that were never contacted. Reaching another host is
// RestrictedSSH's job, because only the hop makes the label true.
type HostInvoker struct {
	host string
}

// NewHostInvoker binds the invoker to the name this machine answers to. The
// name must be the same one the control plane targets, because it is compared
// against the requested target set rather than resolved.
func NewHostInvoker(host string) (*HostInvoker, error) {
	if host == "" {
		return nil, errors.New("host invoker: the local host name is required")
	}
	return &HostInvoker{host: host}, nil
}

// ExecuteInvocation resolves the argv from the verified catalog and executes it
// locally. The catalog, not the caller and not the control plane, decides what
// runs: an invocation names a definition, and Plan produces the sealed argv.
func (invoker *HostInvoker) ExecuteInvocation(ctx context.Context, runner *Runner, catalog *commandpack.Catalog, attemptID string, invocation commandpack.Invocation, suppliedSecrets [][]byte) (Result, error) {
	if invoker == nil || runner == nil || catalog == nil {
		return Result{}, errors.New("host invoker: runner and verified catalog are required")
	}
	if len(invocation.Targets) != 1 || invocation.Targets[0].Name != invoker.host {
		return Result{}, fmt.Errorf("%w: this host answers only for itself", ErrForeignTarget)
	}
	plan, err := catalog.Plan(invocation)
	if err != nil {
		return Result{}, fmt.Errorf("host invoker: resolve verified plan: %w", err)
	}
	// A privileged plan is refused inside ExecuteVerified, which has no sudo
	// adapter. Reaching that refusal here rather than pre-empting it keeps one
	// place deciding what local execution will accept.
	return runner.ExecuteVerified(ctx, attemptID, plan, suppliedSecrets)
}
