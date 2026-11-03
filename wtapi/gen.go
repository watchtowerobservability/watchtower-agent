// Package wtapi is the Go client for the Watchtower API, generated from apps/web/openapi.json.
// Never edit *.gen.go; run `go generate ./wtapi` after the snapshot changes.
package wtapi

//go:generate go run ./prep ../../sdks/api-schema/openapi.json openapi30.gen.json
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.1 -config cfg.yaml openapi30.gen.json
