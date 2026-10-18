package xsts

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const req = `<s:Envelope><s:Body><trust:RequestSecurityToken><wsp:AppliesTo><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><a:Address>http://xboxlive.com</a:Address></EndpointReference></wsp:AppliesTo><auth:AdditionalContext><auth:ContextItem Name="http://schemas.microsoft.com/xbox/2011/07/claims/user/xuid"><auth:Value>0x0009005f5139dadb</auth:Value></auth:ContextItem></auth:AdditionalContext></trust:RequestSecurityToken></s:Body></s:Envelope>`

func TestIssueAndVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := &Handler{Key: []byte("k"), Now: func() time.Time { return now }}
	out, st, why := h.Issue([]byte(req), "478700668470@xbox.com", "0009005f5139dadb:acct-1")
	if st != http.StatusOK {
		t.Fatalf("%d %s", st, why)
	}
	// The console's scanner: literal tags, token between them.
	s := string(out)
	i := strings.Index(s, "<trust:RequestedSecurityToken>") + len("<trust:RequestedSecurityToken>")
	tok := s[i:strings.Index(s, "</trust:RequestedSecurityToken>")]
	c, err := h.Verify(tok)
	if err != nil || c.XUID != "0009005f5139dadb" || c.Account != "acct-1" || c.Audience != "http://xboxlive.com" || c.Kind != "user" {
		t.Fatalf("claims %+v %v", c, err)
	}
	h.Now = func() time.Time { return now.Add(Lifetime + time.Second) }
	if _, err := h.Verify(tok); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := h.Verify(tok + "x"); err == nil {
		t.Fatal("tampered token accepted")
	}
	// A claim for a user who is not signed in on the session is refused.
	if _, st, _ := h.Issue([]byte(req), "c", "0009000000000001:other"); st != http.StatusForbidden {
		t.Fatalf("foreign user status %d", st)
	}
	if _, st, _ := h.Issue([]byte("<x/>"), "c", ""); st != http.StatusBadRequest {
		t.Fatalf("claimless status %d", st)
	}
}
