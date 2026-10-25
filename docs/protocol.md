# Protocol: x360-xsts

The Xbox 360 token service (Xbox Secure Token Service). After a user signs in, the console asks it, over the
security gateway's service tunnel (Live service 33), for a token with a WS-Trust issue request
(`POST /xsts/xsts.svc/IWSTrust13`, audience `http://xboxlive.com`, claim = the user's online XUID) and presents the
result as `Authorization: XBL2.0 x=<token>` to the REST services (profile, progress). The console copies only the
bytes between `<trust:RequestedSecurityToken>` and its closing tag and never validates them, so the token is ours:
`base64url(json claims) "." base64url(hmac-sha256)` with the user's online XUID, OpenPak account id, audience and an
8 h expiry. The REST services verify it with the same key (`xsts.Handler.Verify`).

The user is identified from the gateway session (`X-X360-Users`), never from the claim in the request body: a claim
for a user who is not signed in on the session gets 403.
