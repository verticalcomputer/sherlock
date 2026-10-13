.PHONY: check check-sdk-sync check-typescript eval m11-acceptance test test-dev-pki test-integration test-integration-isolated run-fake-prometheus run-api-mock run-admin-ui run-runner run-investigator migrate-up

check: check-docs
	test -z "$$(gofmt -l .)"
	python3 -m unittest discover -s scripts -p test_release_signing.py
	python3 -m unittest discover -s scripts -p test_export_public_candidate.py
	python3 -m unittest discover -s scripts -p test_prepare_release_review.py
	python3 -m unittest discover -s scripts -p test_build_telemetry_candidate.py
	go vet ./...
	staticcheck ./...
	./scripts/check-sdk-sync.sh
	go test -race ./...
	npm --prefix sdk/typescript run smoke

.PHONY: check-docs context
check-docs:
	python3 -m unittest discover -s scripts -p test_knowledge.py
	python3 scripts/knowledge.py check

context:
	python3 scripts/knowledge.py context

test:
	go test -race ./...

test-dev-pki:
	./scripts/test-generate-dev-pki.sh

test-integration:
	go test -race -tags=integration ./...

test-integration-isolated:
	./scripts/run-isolated-integration.sh

check-typescript:
	npm --prefix sdk/typescript run smoke

check-sdk-sync:
	./scripts/check-sdk-sync.sh

eval:
	go run ./cmd/sherlock-eval -suite test/evals/v1/suite.json
	go run ./cmd/sherlock-eval -replay-suite test/evals/v2/replay-suite.json

m11-acceptance:
	test -n "$(M11_FIXTURE)"
	test -n "$(M11_FIXTURE_SHA256)"
	go run ./cmd/sherlock-m11-acceptance -fixture "$(M11_FIXTURE)" -sha256 "$(M11_FIXTURE_SHA256)"

run-fake-prometheus:
	go run ./cmd/fake-prometheus

run-api-mock:
	go run ./cmd/sherlock-api-mock

run-admin-ui:
	go run ./cmd/sherlock-admin-ui

run-runner:
	go run ./cmd/sherlock-runner

run-investigator:
	go run ./cmd/sherlock-investigator

migrate-up:
	go run ./cmd/sherlock-migrate -dir migrations
