# Xbox 360 XSTS Server

OpenPak's Xbox 360 XSTS Server.

| | |
| --- | --- |
| Network | Xbox 360 |
| Role | Xbox Secure Token Service: WS-Trust issue for signed, expiring user and device tokens |
| Depends on | [`x360-common`](https://github.com/openpak/x360-common) (shared Go library, vendored), [`x360-gateway`](https://github.com/openpak/x360-gateway) (session headers `X-X360-Users`) |
| Used by | REST services that verify the tokens (profile, progress), via `xsts.Handler.Verify` |
| Image | `ghcr.io/openpak/x360-xsts` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `POST /xsts/xsts.svc/IWSTrust13` (Live service 33) | WS-Trust issue request: returns a signed user or device token that the console presents as `Authorization: XBL2.0 x=<token>` |

## Run

```sh
X360_XSTS_KEY=./signing.key go run -mod=vendor ./cmd/x360-xsts
```

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
