# Sherlock generated clients

The Go package in `go` and TypeScript package in `typescript` are generated
artifacts of `api/openapi/sherlock-v1.yaml`. Their public operation names,
models, enum values, query parameters, problem responses, and SSE framing match
that contract. Generated files carry a `DO NOT EDIT` header; contract changes
must begin in the OpenAPI document and regenerate both clients together.
Every generated source embeds the contract SHA-256. CI rejects a contract
change until both SDKs have been regenerated and stamped by the generator.

Run the compatibility checks with:

```sh
go test ./sdk/go ./test/contract
npm --prefix sdk/typescript run smoke
./scripts/check-sdk-sync.sh
```
