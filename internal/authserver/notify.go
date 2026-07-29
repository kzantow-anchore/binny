package authserver

import (
	"strings"

	"github.com/gen2brain/beeep"

	"github.com/anchore/binny/internal/log"
)

// notify is overridable in tests so we don't fire desktop notifications during go test.
var notify = beeep.Notify

func init() {
	beeep.AppName = "binny"
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
func notifyExternalResolve(command []string, cc CommandCredentials) {
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

	if err := notify("binny: resolving credentials", msg, ""); err != nil {
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
