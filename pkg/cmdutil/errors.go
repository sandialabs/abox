// Package cmdutil provides shared utilities for CLI commands.
package cmdutil

import (
	"fmt"
	"strings"

	"github.com/sandialabs/abox/internal/errhint"
)

// ErrCancel signals that the user cancelled an operation.
// Exit code: 0, no output.
type ErrCancel struct{}

func (e *ErrCancel) Error() string { return "cancelled" }

// ErrSilent signals a failure that has already been reported to the user.
// Exit code: 1, no output.
type ErrSilent struct{}

func (e *ErrSilent) Error() string { return "silent error" }

// ErrFlag signals a flag validation error.
// Exit code: 1, error message + command usage printed.
type ErrFlag struct {
	Err error
}

func (e *ErrFlag) Error() string { return e.Err.Error() }
func (e *ErrFlag) Unwrap() error { return e.Err }

// FlagErrorf creates an ErrFlag with a formatted message.
func FlagErrorf(format string, a ...any) error {
	return &ErrFlag{Err: fmt.Errorf(format, a...)}
}

// MutuallyExclusive returns an ErrFlag if more than one of the given
// flag expressions is true. Each label should be the flag name (e.g. "--json").
func MutuallyExclusive(labels []string, values []bool) error {
	var set []string
	for i, v := range values {
		if v && i < len(labels) {
			set = append(set, labels[i])
		}
	}
	if len(set) > 1 {
		return FlagErrorf("specify only one of %s", joinWithOr(set))
	}
	return nil
}

func joinWithOr(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " or " + items[1]
	default:
		var result strings.Builder
		for i, item := range items {
			if i == len(items)-1 {
				result.WriteString("or " + item)
			} else {
				result.WriteString(item + ", ")
			}
		}
		return result.String()
	}
}

// ErrHint is a type alias for errhint.ErrHint, re-exported for convenience.
// See internal/errhint for documentation.
type ErrHint = errhint.ErrHint

// NoResultsError signals that a query succeeded but returned no items.
// Commands can return this to let callers distinguish "empty" from "error".
// By default it exits with code 0 and prints the message.
type NoResultsError struct {
	Message string
}

func (e *NoResultsError) Error() string { return e.Message }
