#!/bin/sh
set -e

# Generate ts-rs type bindings
rm -rf ./landscape-types/src/common
cargo test -p landscape-common export_bindings

# Generate OpenAPI spec → landscape-types/openapi.json
cargo test -p landscape-webserver export_openapi_json -- --nocapture

# Generate orval API client from OpenAPI spec
cd landscape-types && yarn generate
