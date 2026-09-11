//go:build unix

package logutil

import (
	"fmt"
	"log/syslog"
	"sync"
)

// syslogWriter is a package-level syslog writer for logging rotation errors.
// Initialized lazily via sync.Once to avoid data races.
var (
	syslogWriter *syslog.Writer
	syslogOnce   sync.Once
)

// logError logs an error message to syslog if available.
// Falls back silently if syslog is unavailable.
func logError(msg string, err error) {
	syslogOnce.Do(func() {
		w, sysErr := syslog.New(syslog.LOG_WARNING|syslog.LOG_USER, "abox-logutil")
		if sysErr != nil {
			return // syslog unavailable
		}
		syslogWriter = w
	})
	if syslogWriter != nil {
		_ = syslogWriter.Warning(fmt.Sprintf("%s: %v", msg, err))
	}
}
