package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPilotSessionStreamsEnrollmentTokenAndSupervisesProcesses(t *testing.T) {
	root := repositoryRoot(t)
	directory := t.TempDir()
	runtimeDirectory := filepath.Join(directory, "runtime")
	binDirectory := filepath.Join(runtimeDirectory, "bin")
	if err := os.MkdirAll(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	longRunning := "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 0.1; done\n"
	for _, name := range []string{"sherlock-worker", "sherlock-control", "sherlock-api", "sherlock-investigator"} {
		writeExecutable(t, filepath.Join(binDirectory, name), longRunning)
	}
	writeExecutable(t, filepath.Join(binDirectory, "sherlock-admin"), "#!/bin/sh\nprintf '%s\\n' \"$PILOT_TEST_BOOTSTRAP_TOKEN\"\nprintf 'bootstrap metadata\\n' >&2\n")
	tokenCapture := filepath.Join(directory, "token-capture")
	fakeSSH := filepath.Join(directory, "ssh")
	writeExecutable(t, fakeSSH, `#!/bin/sh
case " $* " in
  *" -NT "*) trap 'exit 0' TERM INT; while :; do sleep 0.1; done ;;
  *" test -x "*) exit 0 ;;
  *" enroll "*) cat >"$PILOT_TEST_TOKEN_CAPTURE" ;;
  *"collector_id"*) printf 'collector-new-123\n' ;;
  *) echo "unexpected ssh invocation" >&2; exit 1 ;;
esac
`)

	script := filepath.Join(root, "scripts/sherlock-pilot-session.sh")
	environment := append(os.Environ(),
		"SHERLOCK_PILOT_RUNTIME_DIR="+runtimeDirectory,
		"SHERLOCK_PILOT_SKIP_BUILD=true",
		"SHERLOCK_PILOT_SSH="+fakeSSH,
		"PILOT_TEST_TOKEN_CAPTURE="+tokenCapture,
		"PILOT_TEST_BOOTSTRAP_TOKEN=one-use-bootstrap-token-for-test",
	)
	runPilotScript(t, script, environment, "start", "core")
	t.Cleanup(func() {
		command := exec.Command("bash", script, "stop")
		command.Env = environment
		_ = command.Run()
	})

	runPilotScript(t, script, environment, "enroll-head")
	captured, err := os.ReadFile(tokenCapture)
	if err != nil {
		t.Fatal(err)
	}
	if string(captured) != "one-use-bootstrap-token-for-test\n" {
		t.Fatalf("token pipe carried %q", captured)
	}
	collectorID, err := os.ReadFile(filepath.Join(runtimeDirectory, "collector-id"))
	if err != nil {
		t.Fatal(err)
	}
	if string(collectorID) != "collector-new-123\n" {
		t.Fatalf("collector ID = %q", collectorID)
	}
	if info, err := os.Stat(filepath.Join(runtimeDirectory, "collector-id")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("collector ID mode: info=%v err=%v", info, err)
	}

	err = filepath.Walk(runtimeDirectory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(payload), "one-use-bootstrap-token-for-test") {
			t.Errorf("bootstrap token persisted in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	output := runPilotScript(t, script, environment, "status")
	for _, expected := range []string{"worker RUNNING", "control RUNNING", "tunnel RUNNING", "collector ENROLLED id=collector-new-123"} {
		if !strings.Contains(output, expected) {
			t.Errorf("status missing %q:\n%s", expected, output)
		}
	}
	runPilotScript(t, script, environment, "stop")
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func runPilotScript(t *testing.T, script string, environment []string, arguments ...string) string {
	t.Helper()
	command := exec.Command("bash", append([]string{script}, arguments...)...)
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("pilot session %v failed: %v\n%s", arguments, err, output)
	}
	return string(output)
}
