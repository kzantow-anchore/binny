package cli

import (
	"errors"
	"os"

	"github.com/anchore/binny/cmd/binny/cli/command"
	"github.com/anchore/binny/cmd/binny/cli/internal/ui"
	handler "github.com/anchore/binny/cmd/binny/cli/ui"
	"github.com/anchore/binny/internal/bus"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/binny/internal/redact"
	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
)

// New constructs the `syft packages` command, aliases the root command to `syft packages`,
// and constructs the `syft power-user` command. It is also responsible for
// organizing flag usage and injecting the application config for each command.
// It also constructs the syft attest command and the syft version command.
// `RunE` is the earliest that the complete application configuration can be loaded.
func New(id clio.Identification) clio.Application {
	clioCfg := clio.NewSetupConfig(id).
		WithGlobalConfigFlag().   // add persistent -c <path> for reading an application config from
		WithGlobalLoggingFlags(). // add persistent -v and -q flags tied to the logging config
		WithConfigInRootHelp().   // --help on the root command renders the full application config in the help text
		WithUIConstructor(
			// select a UI based on the logging configuration and state of stdin (if stdin is a tty)
			func(cfg clio.Config) (*clio.UICollection, error) {
				noUI := ui.None(cfg.Log.Quiet)
				if !cfg.Log.AllowUI(os.Stdin) || cfg.Log.Quiet {
					return clio.NewUICollection(noUI), nil
				}

				return clio.NewUICollection(
					ui.New(cfg.Log.Quiet,
						handler.New(handler.DefaultHandlerConfig()),
					),
					noUI,
				), nil
			},
		).
		WithLoggingConfig(clio.LoggingConfig{
			Level: logger.InfoLevel,
		}).
		WithMapExitCode(func(err error) int {
			// a tool executed via `binny run` that exited non-zero has its exit
			// code mirrored so callers see the same status the tool produced
			var toolErr *command.ToolExitError
			if errors.As(err, &toolErr) {
				return toolErr.Code
			}
			return 1
		}).
		WithInitializers(
			func(state *clio.State) error {
				// clio is setting up and providing the bus, redact store, and logger to the application. Once loaded,
				// we can hoist them into the internal packages for global use.
				bus.Set(state.Bus)
				redact.Set(state.RedactStore)
				log.Set(state.Logger)

				return nil
			},
		)

	app := clio.New(*clioCfg)

	root := command.Root(app)

	root.AddCommand(
		clio.VersionCommand(id),
		command.Add(app),
		command.Install(app),
		command.Check(app),
		command.Run(app),
		command.Update(app),
		command.List(app),
		command.Path(app),
		command.Credential(app),
		clio.ConfigCommand(app, clio.DefaultConfigCommandConfig().
			WithReplaceHomeDirWithTilde(true).
			WithIncludeLocationsSubcommand(true)),
	)

	return app
}
