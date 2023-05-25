package logging

import "io"

// A Field is a marshaling operation used to add a key-value pair to a logger's
// context.
type Field struct {
	v any
}

// Logger defines a generic logger for shadowsocks-go.
type Logger interface {
	Fatal(msg string, f ...Field)
	Warn(msg string, f ...Field)
	Info(msg string, f ...Field)
	Debug(msg string, f ...Field)

	Sync() error

	WithField(name string, value any) Field
	WithError(err error) Field

	io.Writer
}
