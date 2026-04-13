package backend

import "errors"

var (
	// ErrNoBackendAvailable is returned when no backend is available on the system.
	ErrNoBackendAvailable = errors.New("no VM backend available on this system")

	// ErrBackendNotFound is returned when a specific backend is requested but not found.
	ErrBackendNotFound = errors.New("requested backend not found")
)
