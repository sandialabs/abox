package cmdutil

import (
	"errors"
	"fmt"
)

// ForEach runs fn for each name, collecting errors prefixed with the name.
// Returns a joined error of all failures, or nil if all succeed.
func ForEach(names []string, fn func(name string) error) error {
	var errs []error
	for _, name := range names {
		if err := fn(name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
