package command

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/anchore/binny/internal/authserver"
	"github.com/anchore/clio"
)

func CredentialEncrypt(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a value with a password and print enc://<base64> for use in config.yaml",
		Long: `Reads a value from stdin (or via a hidden prompt when stdin is a TTY),
prompts for a password (entered twice), encrypts the value with a key derived
from that password (argon2id + AES-256-GCM), and prints "enc://<base64>" to
stdout. Paste the output as a credential value in ~/.binny/config.yaml.

The same password must be supplied to "binny credential serve" so the server
can decrypt the value at resolve time. This command never writes to config
files.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCredentialEncrypt()
		},
	})
}

func runCredentialEncrypt() error {
	value, err := readSecretInput(os.Stdin, "value to encrypt: ")
	if err != nil {
		return fmt.Errorf("reading value: %w", err)
	}
	if len(value) == 0 {
		return fmt.Errorf("empty value")
	}

	password, err := promptNewPassword()
	if err != nil {
		return err
	}

	out, err := authserver.EncryptPassword(password, value)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	if _, err := fmt.Fprintln(os.Stdout, out); err != nil {
		return err
	}
	return nil
}

// readSecretInput reads a secret from in. When in is a TTY, it shows prompt on
// stderr and reads a single line with input hidden; otherwise it consumes the
// full input stream and trims trailing newlines.
func readSecretInput(in *os.File, prompt string) ([]byte, error) {
	if term.IsTerminal(int(in.Fd())) {
		if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
			return nil, err
		}
		b, err := term.ReadPassword(int(in.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		return b, err
	}
	b, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(b, "\r\n"), nil
}
