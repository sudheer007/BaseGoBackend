package observability

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Field represents a structured log field
type Field struct {
	Key   string
	Value interface{}
}

// ToZapField converts Field to zap.Field
func (f Field) ToZapField() zapcore.Field {
	return zap.Any(f.Key, f.Value)
}
