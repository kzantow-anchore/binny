package command

// wrappedExitCode records the exit status of a wrapped tool so the binny process
// can terminate with the same code. A wrapped tool that exits non-zero has
// already written its own diagnostics to stdout/stderr, so binny must stay
// silent and only mirror the code — returning an error here instead would make
// clio print a spurious (empty) error line. main reads this after the CLI runs.
var wrappedExitCode int

// WrappedExitCode returns the exit code recorded for a wrapped/executed tool, or
// 0 when no tool was executed or it exited successfully.
func WrappedExitCode() int { return wrappedExitCode }

func setWrappedExitCode(code int) { wrappedExitCode = code }
