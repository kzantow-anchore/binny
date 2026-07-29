package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/binny/cmd/binny/cli/command"
	"github.com/anchore/binny/cmd/binny/cli/internal/ui"
	handler "github.com/anchore/binny/cmd/binny/cli/ui"
	"github.com/anchore/binny/internal/bus"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/binny/internal/redact"
	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
)

const (
	binnyProgramName = "binny"
)

// New constructs the `syft packages` command, aliases the root command to `syft packages`,
// and constructs the `syft power-user` command. It is also responsible for
// organizing flag usage and injecting the application config for each command.
// It also constructs the syft attest command and the syft version command.
// `RunE` is the earliest that the complete application configuration can be loaded.
// ExitCode returns the process exit code binny should terminate with after the
// CLI has run. It is non-zero when binny wrapped a tool that itself exited
// non-zero, so the wrapped tool's exit status is mirrored to the caller.
func ExitCode() int {
	return command.WrappedExitCode()
}

func New(id clio.Identification) clio.Application {
	wrapped := handleDispatchBySymlink()

	// When binny is invoked as a wrapped tool (e.g. via a `docker` symlink) its
	// own operational logs would pollute the tool's output, so default to only
	// surfacing errors. This still lets critical failures (such as the underlying
	// executable not being found) reach the user, while suppressing the routine
	// install/version-resolution info and warnings.
	defaultLogLevel := logger.InfoLevel
	if wrapped {
		defaultLogLevel = logger.ErrorLevel
	}

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
			Level: defaultLogLevel,
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

// handleDispatchBySymlink rewrites os.Args to handle invocation through symlink:
//   - `binny` (or `binny.exe`): no rewrite, normal CLI dispatch.
//   - `docker-credential-binny`: rewrite to `credential docker-helper <action>`.
//   - any other name: rewrite to `run <name> <args...>`.
//
// It returns true when the invocation is binny wrapping another tool (the
// `run <name>` rewrite), so the caller can quiet binny's own logging.
func handleDispatchBySymlink() bool {
	rewritten, wrapped := rewriteForProgramName(os.Args)
	os.Args = rewritten
	return wrapped
}

func rewriteForProgramName(args []string) (rewritten []string, wrapped bool) {
	if os.Getenv("BINNY_DEBUG") != "" {
		return args, false
	}
	if len(args) == 0 {
		return args, false
	}
	name := strings.TrimSuffix(filepath.Base(args[0]), ".exe")
	switch name {
	case binnyProgramName:
		return args, false
	case command.DockerCredentialHelperName:
		return append([]string{args[0], "credential", command.DockerHelperUse}, args[1:]...), false
	}
	return append([]string{args[0], "run", name}, args[1:]...), true
}
