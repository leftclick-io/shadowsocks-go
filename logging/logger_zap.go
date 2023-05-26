package logging

import (
	"fmt"
	"time"

	"github.com/goccy/go-reflect"
	"go.uber.org/zap"
)

// zapLogger implements Logger.
type zapLogger struct {
	w *zap.Logger
}

// NewZapLogger creates new zap logger.
func NewZapLogger(conf zap.Config) Logger {
	l, err := conf.Build()
	if err != nil {
		panic(err)
	}

	return &zapLogger{w: l}
}

func (l *zapLogger) Sync() error {
	return l.w.Sync()
}

func fieldsToZap(f []Field) []zap.Field {
	n := make([]zap.Field, len(f))

	for i := range f {
		n[i] = f[i].V.(zap.Field)
	}

	return n
}

func (l *zapLogger) Fatal(msg string, f ...Field) {
	l.w.Fatal(msg, fieldsToZap(f)...)
}

func (l *zapLogger) Warn(msg string, f ...Field) {
	l.w.Warn(msg, fieldsToZap(f)...)
}

func (l *zapLogger) Info(msg string, f ...Field) {
	l.w.Info(msg, fieldsToZap(f)...)
}

func (l *zapLogger) Debug(msg string, f ...Field) {
	l.w.Debug(msg, fieldsToZap(f)...)
}

func (l *zapLogger) Write(p []byte) (n int, err error) {
	l.w.Info(string(p))

	return len(p), nil
}

func (l *zapLogger) WithField(name string, value any) Field {
	switch v := value.(type) {
	case string:
		return Field{zap.String(name, v)}

	case *string:
		return Field{zap.Stringp(name, v)}

	case []string:
		return Field{zap.Strings(name, v)}

	case bool:
		return Field{zap.Bool(name, v)}

	case *bool:
		return Field{zap.Boolp(name, v)}

	case time.Duration:
		return Field{zap.Duration(name, v)}

	case int:
		return Field{zap.Int(name, v)}

	case uint:
		return Field{zap.Uint(name, v)}

	case int64:
		return Field{zap.Int64(name, v)}

	case uint32:
		return Field{zap.Uint32(name, v)}

	case uint64:
		return Field{zap.Uint64(name, v)}

	case time.Time:
		return Field{zap.Time(name, v)}

	case fmt.Stringer:
		return Field{zap.Stringer(name, v)}

	default:
		if reflect.TypeOf(value).Kind() == reflect.Slice {
			var a []fmt.Stringer

			s := reflect.ValueOf(value)
			for i := 0; i < s.Len(); i++ {
				a = append(a, s.Index(i).Interface().(fmt.Stringer))
			}

			return Field{zap.Stringers(name, a)}
		}
	}

	panic(fmt.Sprintf("%v: don't know how to handle %v (%T)", name, value, value))
}

func (l *zapLogger) WithError(err error) Field {
	return Field{zap.Error(err)}
}
