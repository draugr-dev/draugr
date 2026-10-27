package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// Everything `draugr login`, `draugr logout` and doctor's login line print, in one file so the
// wording changes in one place. Painted the way the report paints a section: the heading and the
// labels dim, an outcome in its own color, and facts joined by a dim ` · `.

// loginClockLayout is how a token's expiry is written.
const loginClockLayout = "15:04 UTC"

// writeLoginBlock is the request awaiting approval: the code to enter, where to enter it, and how
// long the code lasts.
func writeLoginBlock(w io.Writer, col tui.Painter, server string, a login.Authorization) {
	_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, "LOGIN")+"  "+server)
	_, _ = fmt.Fprintln(w, "  "+col.Paint(tui.StyleMuted, "code   ")+"  "+col.Paint(tui.StyleStrong, a.UserCode))
	_, _ = fmt.Fprintln(w, "  "+col.Paint(tui.StyleMuted, "open   ")+"  "+a.VerificationURI)
	_, _ = fmt.Fprintln(w, "  "+col.Paint(tui.StyleMuted, "expires")+"  "+lifetime(a.Lifetime()))
	_, _ = fmt.Fprintln(w)
}

// loginApprovedLine is printed once the login is stored.
func loginApprovedLine(col tui.Painter, l login.Login) string {
	parts := whose(l)
	if !l.Expires.IsZero() {
		until := "until " + l.Expires.UTC().Format(loginClockLayout)
		if !l.Issued.IsZero() {
			until += " (" + lifetime(l.Expires.Sub(l.Issued)) + ")"
		}
		parts = append(parts, until)
	}
	return facts(col, tui.StylePass, "approved", parts...)
}

// loginDeniedError ends a request somebody denied.
func loginDeniedError(a login.Authorization) error {
	return errors.New(facts(tui.Plain(), tui.StyleNone, "denied", a.UserCode, "nothing stored"))
}

// loginExpiredError ends a request nobody approved before its code expired.
func loginExpiredError(server string, a login.Authorization) error {
	return errors.New(facts(tui.Plain(), tui.StyleNone, "expired", a.UserCode,
		"not approved within "+lifetime(a.Lifetime()), "run `draugr login "+server+"` again"))
}

// loginNotStoredError ends a login the keychain would not keep. The token was revoked, or the
// revocation failed too and why is joined to this.
func loginNotStoredError(err error) error {
	return fmt.Errorf("%s: %w", facts(tui.Plain(), tui.StyleNone, "not stored", "token revoked",
		"set $DRAUGR_API_TOKEN instead"), err)
}

// logoutLine is printed once the login is revoked and removed.
func logoutLine(col tui.Painter, l login.Login) string {
	return facts(col, tui.StylePass, "logged out", append([]string{l.Server}, append(whose(l), "token revoked")...)...)
}

// logoutNoneLine is printed where there was no login to remove.
func logoutNoneLine(col tui.Painter, server string) string {
	return facts(col, tui.StyleMuted, "not logged in", server)
}

// logoutNotRevokedError ends a logout that removed the login and could not tell the server.
func logoutNotRevokedError(l login.Login, why error) error {
	parts := []string{l.Server, "removed from the keychain"}
	if !l.Expires.IsZero() {
		parts = append(parts, "valid until "+l.Expires.UTC().Format(loginClockLayout))
	}
	return fmt.Errorf("%s: %w", facts(tui.Plain(), tui.StyleNone, "not revoked", parts...), why)
}

// doctorLoginLine is the line under doctor's POLICY heading naming whose login asked.
func doctorLoginLine(col tui.Painter, l login.Login) string {
	parts := whose(l)
	if !l.Expires.IsZero() {
		parts = append(parts, "until "+l.Expires.UTC().Format(loginClockLayout))
	}
	return "  " + col.Paint(tui.StyleMuted, "login") + "  " + joinFacts(col, parts)
}

// facts is an outcome followed by facts, joined by a dim ` · `. Empty facts are left out.
func facts(col tui.Painter, style tui.Style, outcome string, parts ...string) string {
	return joinFacts(col, append([]string{col.Paint(style, outcome)}, parts...))
}

// joinFacts joins the facts that are not empty with a dim ` · `.
func joinFacts(col tui.Painter, parts []string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, col.Paint(tui.StyleMuted, " · "))
}

// whose is the account and organization a login belongs to.
func whose(l login.Login) []string {
	return []string{l.Email, l.Organization}
}

// lifetime writes a duration in its largest whole unit: "12h", "15m", and anything else as
// shortDuration does.
func lifetime(d time.Duration) string {
	switch {
	case d > 0 && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d > 0 && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return shortDuration(d)
}
