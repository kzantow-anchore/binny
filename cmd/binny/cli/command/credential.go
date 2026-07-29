package command

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Credential(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred"},
		Short:   "Manage and serve credentials for binny clients",
	})

	cmd.AddCommand(
		CredentialServe(app),
		CredentialEncrypt(app),
		CredentialCheck(app),
		CredentialDockerHelper(app),
	)

	return cmd
}
