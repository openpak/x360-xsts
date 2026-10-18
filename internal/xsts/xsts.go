// Package xsts is the Xbox 360 token service (Xbox Secure Token Service): the
// console asks it, over the security gateway's service tunnel (Live service 33),
// for a token it then presents as "Authorization: XBL2.0 x=<token>" to the REST
// services (profile, progress). The console only copies the bytes between
// <trust:RequestedSecurityToken> and its closing tag, never validates them, so the
// token is ours to define: a signed, expiring blob naming the user.
package xsts

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/openpak/x360-common/wire"
	"github.com/openpak/x360-common/xstoken"
)

// Path is the endpoint the console posts the WS-Trust issue request to.
const Path = "/xsts/xsts.svc/IWSTrust13"

// Lifetime is how long an issued token is valid; the console decides how long it
// caches one, the REST services check Verify.
const Lifetime = 8 * time.Hour

const maxBody = 16 << 10

var (
	reAudience = regexp.MustCompile(`<a:Address>([^<]*)</a:Address></EndpointReference>`)
	reUser     = regexp.MustCompile(`claims/user/xuid"><auth:Value>(?:0x)?([0-9a-fA-F]{1,16})</auth:Value>`)
	reDevice   = regexp.MustCompile(`claims/device/id"><auth:Value>(?:0x)?([0-9a-fA-F]{1,16})</auth:Value>`)
)

// Handler issues tokens.
type Handler struct {
	Key []byte // HMAC-SHA256 signing key
	Now func() time.Time
	Log *slog.Logger
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Sign and Verify delegate to the shared token package.
func (h *Handler) signer() *xstoken.Signer { return &xstoken.Signer{Key: h.Key, Now: h.Now} }

// Sign encodes c.
func (h *Handler) Sign(c xstoken.Claims) string { return h.signer().Sign(c) }

// Verify checks a token's signature and expiry.
func (h *Handler) Verify(tok string) (xstoken.Claims, error) { return h.signer().Verify(tok) }

// sessionUsers parses the gateway's X-X360-Users header ("xuidhex:account,...").
func sessionUsers(v string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(v, ",") {
		if x, a, ok := strings.Cut(strings.TrimSpace(p), ":"); ok {
			m[strings.ToLower(x)] = a
		}
	}
	return m
}

// Issue answers the request body with a response, or an HTTP status and reason.
func (h *Handler) Issue(body []byte, account, users string) ([]byte, int, string) {
	req := string(body)
	aud := ""
	if m := reAudience.FindStringSubmatch(req); m != nil {
		aud = m[1]
	}
	var c xstoken.Claims
	switch {
	case reUser.MatchString(req):
		m := reUser.FindStringSubmatch(req)
		x := fmt.Sprintf("%016s", strings.ToLower(m[1]))
		x = strings.ReplaceAll(x, " ", "0")
		acct, ok := sessionUsers(users)[x]
		if !ok { // the SG session, not the claim, says who is signed in
			return nil, http.StatusForbidden, "user is not signed in on this session"
		}
		c = xstoken.Claims{Kind: "user", XUID: x, Account: acct}
	case reDevice.MatchString(req):
		m := reDevice.FindStringSubmatch(req)
		c = xstoken.Claims{Kind: "device", XUID: strings.ToLower(m[1])}
	default:
		return nil, http.StatusBadRequest, "no xuid or device claim"
	}
	c.Audience = aud
	c.Expires = h.now().Add(Lifetime).Unix()
	tok := h.Sign(c)
	rstr := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` +
		`<trust:RequestSecurityTokenResponseCollection xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">` +
		`<trust:RequestSecurityTokenResponse><trust:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</trust:TokenType>` +
		`<trust:RequestedSecurityToken>` + tok + `</trust:RequestedSecurityToken>` +
		`</trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection></s:Body></s:Envelope>`
	h.log().Info("token issued", "kind", c.Kind, "xuid", c.XUID, "audience", aud, "console", account)
	return []byte(rstr), http.StatusOK, ""
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.URL.Path, Path) || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	out, status, why := h.Issue(body, r.Header.Get(wire.AccountHeader), r.Header.Get(wire.UsersHeader))
	if status != http.StatusOK {
		h.log().Info("token refused", "status", status, "why", why, "console", r.Header.Get(wire.AccountHeader), "body_len", len(body))
		http.Error(w, why, status)
		return
	}
	// The console's HTTP stack parses Date strictly and converts it with
	// SystemTimeToFileTime; it needs none, so send none (a nil value stops net/http
	// adding its own). Content-Type is not checked either: keep it minimal.
	w.Header()["Date"] = nil
	w.Header().Set("Content-Type", "application/soap+xml")
	w.Header().Set("Content-Length", fmt.Sprint(len(out)))
	w.Write(out)
}
