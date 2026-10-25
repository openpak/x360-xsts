# Deploy: x360-xsts

## Configuration

`X360_XSTS_ADDR` (default `:10033`), `X360_XSTS_KEY` (signing key file, created 0600 with 32 random bytes on first
start), `X360_XSTS_DEBUG`. See `deploy/openpak-x360-xsts.container`; Traefik routes `PathPrefix(/xsts)` on the plain-HTTP
entrypoint to it (the gateway proxies every service port to the primary's Traefik).

## Build and test

`go test -mod=vendor ./...`. Tag `vX.Y.Z` and CI publishes `ghcr.io/openpak/x360-xsts:latest` (amd64 + arm64); hosts
auto-update `:latest`. The request/response format comes from the XAM analysis in the Wharf notes (xrl-schema-opcodes.md
section 14). Licensed AGPL-3.0, see LICENSE.
