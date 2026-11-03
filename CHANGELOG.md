# Changelog

- 2026-11-03: v0.9.4: Every request logs one stderr line, `http <method> <path> -> <status> <duration>ms` (x360-common v0.5.1 `httplog`): no query, headers, cookies, tokens or bodies; `/healthz` skipped.

- 2026-10-18: v0.9.0 first release: `POST /xsts/xsts.svc/IWSTrust13` answers the console's WS-Trust issue request
  with a signed, expiring user/device token (RSTR the console's tag scanner accepts); the user comes from the gateway
  session. `xsts.Handler.Verify` for the REST services.

- 2026-10-18: v0.9.1 minimal response headers (no Date, Content-Type application/soap+xml): the console's HTTP stack
  parses Date strictly.

- 2026-10-18: v0.9.2 token sign/verify moved to x360-common/xstoken (shared with the REST services).
