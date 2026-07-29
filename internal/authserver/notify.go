package authserver

import (
	"strings"

	"github.com/gen2brain/beeep"

	"github.com/anchore/binny/internal/log"
)

func init() {
	beeep.AppName = "binny"
}

// Notifier delivers a desktop notification. DesktopNotifier is the production
// implementation; a Resolver holds one (nil disables notifications), so tests
// can inject a capture without any package-level state.
type Notifier func(title, message string) error

// DesktopNotifier sends a native desktop notification via beeep.
func DesktopNotifier(title, message string) error {
	return beeep.Notify(title, message, "")
}

// notifyExternalResolve fires a desktop notification for a command whose
// external (op://) credentials were resolved silently — that is, without the
// user being shown an approval dialog. The caller only invokes it in that case:
// when a dialog is shown the dialog is itself the notification, and a denied
// request resolves nothing to notify about. The notification is ephemeral; on
// macOS and Windows it follows the OS notification-center defaults (banners
// auto-dismiss within ~10s), and on Linux notify-send honors the daemon's
// expire-time. Failures are logged at debug — a missing or broken notifier must
// not block credential resolution.
func notifyExternalResolve(notify Notifier, command []string, cc CommandCredentials) {
	if !hasExternalRef(cc) {
		return
	}
	msg := strings.Join(command, " ")

	var refs []string
	for _, e := range cc.Env {
		refs = append(refs, e.Token)
	}
	if cc.Docker != nil {
		refs = append(refs, cc.Docker.Password)
	}
	msg += "\n---------------\n"
	msg += cc.Name + "\n  ↳ " + strings.Join(refs, ", ")

	if err := notify("binny: resolving credentials", msg); err != nil {
		log.Debugf("desktop notification failed: %v", err)
	}
}

func hasExternalRef(cc CommandCredentials) bool {
	for _, e := range cc.Env {
		if strings.HasPrefix(e.Token, opPrefix) {
			return true
		}
	}
	if cc.Docker != nil {
		if strings.HasPrefix(cc.Docker.Username, opPrefix) || strings.HasPrefix(cc.Docker.Password, opPrefix) {
			return true
		}
	}
	return false
}
