package app

import (
	"log"
	"os"
)

// newLogger builds a role logger. systemd's journal timestamps every line
// itself (and sets $JOURNAL_STREAM when stdio is connected to it), so under
// journald we drop the Go date/time to avoid a second, redundant timestamp.
// Run from a terminal, it keeps the standard date/time.
func newLogger(prefix string) *log.Logger {
	flags := log.LstdFlags | log.Lmsgprefix
	if os.Getenv("JOURNAL_STREAM") != "" {
		flags = log.Lmsgprefix
	}
	return log.New(os.Stderr, prefix, flags)
}
