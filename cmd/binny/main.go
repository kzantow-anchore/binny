package main

import (
	"os"

	"github.com/anchore/binny/cmd/binny/cli"
	"github.com/anchore/clio"
)

// applicationName is the non-capitalized name of the application (do not change this)
const (
	applicationName = "binny"
	notProvided     = "[not provided]"
)

// all variables here are provided as build-time arguments, with clear default values
var (
	version        = notProvided
	buildDate      = notProvided
	gitCommit      = notProvided
	gitDescription = notProvided
)

func main() {
	app := cli.New(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	app.Run()

	// app.Run() only calls os.Exit for its own error path; mirror a wrapped
	// tool's non-zero exit status here so `docker …` (resolved to binny) returns
	// the same code the real docker would have.
	os.Exit(cli.ExitCode())
}
