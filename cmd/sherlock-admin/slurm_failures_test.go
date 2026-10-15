package main

import "testing"

func TestSlurmFailureAdminRequiresExplicitScopeAndRevision(t *testing.T) {
	valid := []string{"enroll", "--cluster", "c", "--source", "s", "--namespace", "slurm", "--policy-id", "p", "--actor", "operator", "--expected-revision", "0"}
	c, err := parseSlurmFailureCommand(valid)
	if err != nil || c.policy.Threshold != 3 || c.policy.WindowSeconds != 1800 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, args := range [][]string{
		{"disable", "--cluster", "c", "--policy-id", "p", "--actor", "op", "--expected-revision", "0"},
		{"status", "--cluster", "c", "--policy-id", "p", "--actor", "op"},
		append(append([]string{}, valid...), "--threshold", "1"),
		append(append([]string{}, valid...), "--window", "1.5s"),
		append(append([]string{}, valid...), "--source", "other"),
	} {
		if _, err := parseSlurmFailureCommand(args); err == nil {
			t.Fatalf("invalid admin command accepted: %v", args)
		}
	}
}
