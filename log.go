package wireproxy

import (
	"log"
	"sync/atomic"
)

// LogLevel selects which informational messages wireproxy prints. Errors are
// always printed.
type LogLevel int32

const (
	// LogError prints errors only.
	LogError LogLevel = iota
	// LogInfo also prints startup and lifecycle messages (the default).
	LogInfo
	// LogDebug also prints a line for every request handled.
	LogDebug
)

var logLevel atomic.Int32

func init() {
	logLevel.Store(int32(LogInfo))
}

// SetLogLevel sets the verbosity of wireproxy's own log messages. It does not
// affect the wireguard device logger, which is configured in StartWireguard.
func SetLogLevel(level LogLevel) {
	logLevel.Store(int32(level))
}

func logEnabled(level LogLevel) bool {
	return LogLevel(logLevel.Load()) >= level
}

func infof(format string, args ...any) {
	if logEnabled(LogInfo) {
		log.Printf(format, args...)
	}
}

func debugf(format string, args ...any) {
	if logEnabled(LogDebug) {
		log.Printf(format, args...)
	}
}
