// Package errhint defines ErrHint, a structured error that pairs an error
// with a user-facing remediation hint. The CLI error handler renders the
// hint below the error message.
package errhint

// ErrHint wraps an error with a user-facing remediation hint.
// The hint is displayed below the error message by the CLI error handler.
// Error messages should be clean single-line strings; multi-line guidance
// (e.g. "run this command", "try this instead") belongs in the Hint field.
type ErrHint struct {
	Err  error
	Hint string
}

func (e *ErrHint) Error() string { return e.Err.Error() }
func (e *ErrHint) Unwrap() error { return e.Err }
