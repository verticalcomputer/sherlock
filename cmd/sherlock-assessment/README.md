# Sherlock assessment CLI

Run the assessment commands from the repository root.

    go run ./cmd/sherlock-assessment validate-config -config test/assessment/v1/config.json
    go run ./cmd/sherlock-assessment replay -suite test/assessment/v1/suite.json -out /path/to/new/report
    go run ./cmd/sherlock-assessment export -run RUN_ID -out /path/to/new/archive
    go run ./cmd/sherlock-assessment replay -archive /path/to/archive -out /path/to/new/report

Validation and replay run offline. Export uses the dedicated
SHERLOCK_ASSESSMENT_DATABASE_URL and a read-only snapshot. Export requires a
closed run within its seven-day retention period.

Outputs use private permissions and require a new directory. The final
manifest identifies complete output. The INCOMPLETE marker identifies a failed
write. Replay reports include semantic decisions, execution timestamps,
label statistics, and retained evidence. Archive replay provides observed
decisions and ideal reconstruction in separate files and identifies candidates
whose execution failures could not be reproduced.

Exit 0 indicates success. Exit 2 indicates invalid arguments, schema, limits
or an unavailable replay version. Exit 3 indicates a filesystem or database
failure. Exit 4 indicates a deterministic mismatch.
