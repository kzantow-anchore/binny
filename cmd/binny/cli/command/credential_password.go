package command

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readHiddenLine reads a single line without echoing it, prompting on stderr.
// It prefers stdin when that is a terminal; otherwise it opens the controlling
// terminal (/dev/tty) so a password can still be prompted for even when stdin
// is a pipe (e.g. the value being encrypted is piped in). It errors when no
// terminal is available.
func readHiddenLine(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readHiddenFrom(os.Stdin, prompt)
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("no terminal available to prompt for password: %w", err)
	}
	defer func() { _ = tty.Close() }()
	return readHiddenFrom(tty, prompt)
}

func readHiddenFrom(f *os.File, prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(f.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	return string(b), err
}

// promptNewPassword prompts for a password twice and requires the two entries
// to match, so a typo doesn't produce an undecryptable value.
func promptNewPassword() (string, error) {
	pw, err := readHiddenLine("credential password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errors.New("password is required")
	}
	confirm, err := readHiddenLine("confirm password: ")
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", errors.New("passwords do not match")
	}
	return pw, nil
}

// acquireServePassword obtains the enc:// decryption password for the running
// server: a hidden prompt when stdin is a terminal, otherwise the trimmed
// contents of stdin so `echo pw | binny credential serve` works for automation.
func acquireServePassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readHiddenLine("credential password: ")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading credential password from stdin: %w", err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
