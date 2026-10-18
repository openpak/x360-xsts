# x360-xsts

The Xbox 360 token service (Xbox Secure Token Service). After a user signs in, the console asks it, over the
security gateway's service tunnel (Live service 33), for a token with a WS-Trust issue request
(`POST /xsts/xsts.svc/IWSTrust13`, audience `http://xboxlive.com`, claim = the user's online XUID) and presents the
result as `Authorization: XBL2.0 x=<token>` to the REST services (profile, progress). The console copies only the
bytes between `<trust:RequestedSecurityToken>` and its closing tag and never validates them, so the token is ours:
`base64url(json claims) "." base64url(hmac-sha256)` with the user's online XUID, OpenPak account id, audience and an
8 h expiry. The REST services verify it with the same key (`xsts.Handler.Verify`).

The user is identified from the gateway session (`X-X360-Users`), never from the claim in the request body: a claim
for a user who is not signed in on the session gets 403.

Part of OpenPak's Xbox 360 stack: one repository and one image per service ([`x360-kdc`](../x360-kdc),
[`x360-gateway`](../x360-gateway), [`x360-xuacs`](../x360-xuacs), [`x360-liveinfo`](../x360-liveinfo),
[`x360-xsts`](.), [`x360-notice`](../x360-notice), [`x360-xexds`](../x360-xexds)) around the shared Go library
[`x360-common`](../x360-common) (`replace` + committed `vendor/`; after changing x360-common run `go mod vendor` here and commit).

## Configuration

`X360_XSTS_ADDR` (default `:10033`), `X360_XSTS_KEY` (signing key file, created 0600 with 32 random bytes on first
start), `X360_XSTS_DEBUG`. See `deploy/openpak-x360-xsts.container`; Traefik routes `PathPrefix(/xsts)` on the plain-HTTP
entrypoint to it (the gateway proxies every service port to the primary's Traefik).

## Build and test

`go test -mod=vendor ./...`. Tag `vX.Y.Z` and CI publishes `ghcr.io/openpak/x360-xsts:latest` (amd64 + arm64); hosts
auto-update `:latest`. The request/response format comes from the XAM analysis in the Wharf notes (xrl-schema-opcodes.md
section 14). Licensed AGPL-3.0, see LICENSE.
