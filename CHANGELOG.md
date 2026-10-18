# Changelog

- 2026-10-18: v0.9.0 first release: `POST /xsts/xsts.svc/IWSTrust13` answers the console's WS-Trust issue request
  with a signed, expiring user/device token (RSTR the console's tag scanner accepts); the user comes from the gateway
  session. `xsts.Handler.Verify` for the REST services.
