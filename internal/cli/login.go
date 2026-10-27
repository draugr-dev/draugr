package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// loginClient builds the device-flow client for a server, swapped in tests to skip the waits.
var loginClient = func(server string) (login.Client, error) {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return login.NewClient(server, login.Device{Name: host, Version: version.Version})
}

func newLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login [server]",
		Short: "Sign in to a Draugr server for the organization-policy check",
		Long: "Sign in to a Draugr server by device authorization, approving the request in the browser.\n\n" +
			"The token is check-only and lasts until the server's expiry. It is kept in the OS keychain,\n" +
			"never in a file, and used by `draugr doctor --policy` and the scan's policy check when\n" +
			"$DRAUGR_API_TOKEN is not set. It never publishes a run.\n\n" +
			"The server defaults to $DRAUGR_API_URL.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, err := serverArg(args)
			if err != nil {
				return err
			}
			return runLogin(cmd.Context(), cmd.OutOrStdout(), server)
		},
	}
	return cmd
}

func newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout [server]",
		Short: "Revoke the login for a Draugr server and remove it from the keychain",
		Long: "Tell the server to revoke the token `draugr login` stored, and remove it from the OS keychain.\n\n" +
			"The server defaults to $DRAUGR_API_URL.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, err := serverArg(args)
			if err != nil {
				return err
			}
			return runLogout(cmd.Context(), cmd.OutOrStdout(), server)
		},
	}
}

// serverArg is the server a login command names, else $DRAUGR_API_URL.
func serverArg(args []string) (string, error) {
	server := os.Getenv("DRAUGR_API_URL")
	if len(args) == 1 {
		server = args[0]
	}
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		return "", errors.New("name the server, such as `draugr login https://draugr.example`, or set $DRAUGR_API_URL")
	}
	if _, err := login.Origin(server); err != nil {
		return "", err
	}
	return server, nil
}

func runLogin(ctx context.Context, w io.Writer, server string) error {
	if netpolicy.Offline() {
		return netpolicy.Refuse("draugr login", server+"/v1/device/code")
	}
	origin, err := login.Origin(server)
	if err != nil {
		return err
	}
	client, err := loginClient(server)
	if err != nil {
		return err
	}
	auth, err := client.Authorize(ctx)
	if err != nil {
		return fmt.Errorf("draugr login %s: %w", server, err)
	}
	col := tui.For(w)
	writeLoginBlock(w, col, server, auth)
	l, err := client.Wait(ctx, auth)
	switch {
	case errors.Is(err, login.ErrDenied):
		return loginDeniedError(auth)
	case errors.Is(err, login.ErrExpired):
		return loginExpiredError(server, auth)
	case err != nil:
		return fmt.Errorf("draugr login %s: %w", server, err)
	}
	if err := loginStore().Set(origin, l); err != nil {
		// A token nobody holds is still live until it expires, so it is ended rather than left.
		if rerr := client.Revoke(context.WithoutCancel(ctx), l.Token); rerr != nil {
			return errors.Join(loginNotStoredError(err), rerr)
		}
		return loginNotStoredError(err)
	}
	_, _ = fmt.Fprintln(w, loginApprovedLine(col, l))
	return nil
}

func runLogout(ctx context.Context, w io.Writer, server string) error {
	origin, err := login.Origin(server)
	if err != nil {
		return err
	}
	store := loginStore()
	l, err := store.Get(origin)
	if errors.Is(err, login.ErrNotLoggedIn) {
		_, _ = fmt.Fprintln(w, logoutNoneLine(tui.For(w), server))
		return nil
	}
	if err != nil {
		return err
	}
	var revokeErr error
	if netpolicy.Offline() {
		revokeErr = netpolicy.Refuse("revoking the token", l.Server+"/v1/device/revoke")
	} else if client, cerr := loginClient(l.Server); cerr != nil {
		revokeErr = cerr
	} else {
		revokeErr = client.Revoke(ctx, l.Token)
	}
	if err := store.Delete(origin); err != nil && !errors.Is(err, login.ErrNotLoggedIn) {
		return err
	}
	if revokeErr != nil {
		return logoutNotRevokedError(l, revokeErr)
	}
	_, _ = fmt.Fprintln(w, logoutLine(tui.For(w), l))
	return nil
}
