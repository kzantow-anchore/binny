package authserver

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// dialogTitle is the title shown on every approval dialog.
const dialogTitle = "binny"

// defaultDialogTimeout bounds how long a dialog waits for a response when ctx
// carries no earlier deadline.
const defaultDialogTimeout = 60 * time.Second

// nativePrompter shows a host-native confirmation dialog. The client-supplied
// command text is always passed to the dialog helper out-of-band (argv or env),
// never interpolated into a script string, so a malicious argument cannot inject
// AppleScript / shell / PowerShell.
type nativePrompter struct{}

// NewNativePrompter returns the default Prompter, which shells out to the
// platform's native dialog helper (osascript on macOS, zenity/kdialog on Linux,
// PowerShell on Windows). It fails closed (returns an error) when no helper is
// available, so a headless server without --auto-approve denies rather than
// silently allowing.
func NewNativePrompter() Prompter { return nativePrompter{} }

func (nativePrompter) Confirm(ctx context.Context, req PromptRequest) (bool, error) {
	text := promptText(req)
	timeout := dialogSeconds(ctx)
	switch runtime.GOOS {
	case "darwin":
		return macConfirm(ctx, text, timeout)
	case "windows":
		return windowsConfirm(ctx, text)
	default:
		return unixConfirm(ctx, text, timeout)
	}
}

// dialogSeconds returns how long a dialog should wait before giving up: the
// time until ctx's deadline (less a small buffer so we return before the caller
// cancels), or defaultDialogTimeout when ctx has no deadline.
func dialogSeconds(ctx context.Context) int {
	secs := int(defaultDialogTimeout / time.Second)
	if dl, ok := ctx.Deadline(); ok {
		remaining := int(time.Until(dl)/time.Second) - 2
		if remaining < 1 {
			remaining = 1
		}
		secs = remaining
	}
	return secs
}

// macConfirm shows an osascript dialog. The message is passed as argv (via
// `on run argv`) rather than embedded in the script, so it cannot break out of
// the string literal.
func macConfirm(ctx context.Context, text string, timeout int) (bool, error) {
	script := fmt.Sprintf(
		`on run argv
display dialog (item 1 of argv) with title %q buttons {"Deny", "Allow"} default button "Allow" with icon caution giving up after %d
end run`,
		dialogTitle, timeout)
	out, err := exec.CommandContext(ctx, "osascript", "-e", script, "--", text).Output()
	if err != nil {
		// A non-zero exit here is an osascript failure (no GUI session, etc.), not
		// a user denial: fail closed with a helpful error.
		return false, fmt.Errorf("displaying approval dialog: %w", err)
	}
	// "gave up:true" means the dialog timed out; anything other than an explicit
	// Allow is treated as denial.
	res := string(out)
	if strings.Contains(res, "gave up:true") {
		return false, nil
	}
	return strings.Contains(res, "button returned:Allow"), nil
}

// unixConfirm prefers zenity, falling back to kdialog. Arguments are passed as
// separate argv elements (exec does not invoke a shell), so the message text is
// not subject to shell interpretation.
func unixConfirm(ctx context.Context, text string, timeout int) (bool, error) {
	if path, err := exec.LookPath("zenity"); err == nil {
		cmd := exec.CommandContext(ctx, path,
			"--question",
			"--title="+dialogTitle,
			"--text="+text,
			"--ok-label=Allow",
			"--cancel-label=Deny",
			"--timeout="+strconv.Itoa(timeout),
		)
		// zenity exits 0 on the OK/affirmative button, non-zero on Deny or timeout.
		return cmd.Run() == nil, nil
	}
	if path, err := exec.LookPath("kdialog"); err == nil {
		cmd := exec.CommandContext(ctx, path, "--title", dialogTitle, "--yesno", text)
		return cmd.Run() == nil, nil
	}
	return false, fmt.Errorf("no dialog helper found (install zenity or kdialog, or run the server with --auto-approve)")
}

// windowsConfirm shows a PowerShell message box. The message is passed via an
// environment variable and referenced as $env:BINNY_PROMPT_TEXT so it is never
// spliced into the script source.
func windowsConfirm(ctx context.Context, text string) (bool, error) {
	const script = `Add-Type -AssemblyName System.Windows.Forms; ` +
		`$r = [System.Windows.Forms.MessageBox]::Show($env:BINNY_PROMPT_TEXT, 'binny', ` +
		`[System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning); ` +
		`if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "BINNY_PROMPT_TEXT="+text)
	return cmd.Run() == nil, nil
}
