package observability

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogLevel represents the log level
type LogLevel string

const (
	// Log levels
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarn    LogLevel = "warn"
	LogLevelError   LogLevel = "error"
	LogLevelFatal   LogLevel = "fatal"
)

// LoggingConfig holds configuration for logging
type LoggingConfig struct {
	Level      LogLevel
	JSONFormat bool
	OutputPath string
}

// DefaultLoggingConfig returns a default configuration for logging
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Level:      LogLevelInfo,
		JSONFormat: true,
		OutputPath: "",
	}
}

// Logger provides structured logging
type Logger struct {
	zap           *zap.Logger
	metrics       *Metrics
	contextFields []zapcore.Field
}

// NewLogger creates a new logger
func NewLogger(cfg *LoggingConfig, metrics *Metrics) (*Logger, error) {
	if cfg == nil {
		cfg = DefaultLoggingConfig()
	}

	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create encoder
	var encoder zapcore.Encoder
	if cfg.JSONFormat {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create writer
	var writer zapcore.WriteSyncer
	if cfg.OutputPath == "" {
		writer = zapcore.AddSync(os.Stdout)
	} else {
		file, err := os.OpenFile(cfg.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writer = zapcore.AddSync(file)
	}

	// Create core
	var zapLevel zapcore.Level
	switch cfg.Level {
	case LogLevelDebug:
		zapLevel = zapcore.DebugLevel
	case LogLevelInfo:
		zapLevel = zapcore.InfoLevel
	case LogLevelWarn:
		zapLevel = zapcore.WarnLevel
	case LogLevelError:
		zapLevel = zapcore.ErrorLevel
	case LogLevelFatal:
		zapLevel = zapcore.FatalLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	core := zapcore.NewCore(encoder, writer, zap.NewAtomicLevelAt(zapLevel))

	// Create logger
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		zap:     logger,
		metrics: metrics,
	}, nil
}

// WithField returns a new logger with a field added to the context
func (l *Logger) WithField(key string, value interface{}) *Logger {
	if l == nil {
		return nil
	}

	contextFields := make([]zapcore.Field, len(l.contextFields)+1)
	copy(contextFields, l.contextFields)
	contextFields[len(contextFields)-1] = zap.Any(key, value)

	return &Logger{
		zap:           l.zap,
		metrics:       l.metrics,
		contextFields: contextFields,
	}
}

// WithFields returns a new logger with fields added to the context
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	if l == nil {
		return nil
	}

	contextFields := make([]zapcore.Field, len(l.contextFields)+len(fields))
	copy(contextFields, l.contextFields)

	i := len(l.contextFields)
	for k, v := range fields {
		contextFields[i] = zap.Any(k, v)
		i++
	}

	return &Logger{
		zap:           l.zap,
		metrics:       l.metrics,
		contextFields: contextFields,
	}
}

// WithContext returns a new logger with fields from context
func (l *Logger) WithContext(ctx context.Context) *Logger {
	if l == nil {
		return nil
	}

	// Add request ID if available
	if reqID, ok := ctx.Value("request_id").(string); ok {
		return l.WithField("request_id", reqID)
	}

	return l
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...zapcore.Field) {
	if l == nil {
		return
	}

	allFields := l.mergeFields(fields)
	l.zap.Debug(msg, allFields...)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...zapcore.Field) {
	if l == nil {
		return
	}

	allFields := l.mergeFields(fields)
	l.zap.Info(msg, allFields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...zapcore.Field) {
	if l == nil {
		return
	}

	allFields := l.mergeFields(fields)
	l.zap.Warn(msg, allFields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, fields ...zapcore.Field) {
	if l == nil {
		return
	}

	// Record metric
	if l.metrics != nil {
		l.metrics.RecordError("application", "unknown")
	}

	allFields := make([]zapcore.Field, 0, len(fields)+len(l.contextFields)+1)
	allFields = append(allFields, l.contextFields...)
	allFields = append(allFields, fields...)
	
	if err != nil {
		allFields = append(allFields, zap.Error(err))
	}

	l.zap.Error(msg, allFields...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, err error, fields ...zapcore.Field) {
	if l == nil {
		os.Exit(1)
		return
	}

	// Record metric
	if l.metrics != nil {
		l.metrics.RecordError("fatal", "unknown")
	}

	allFields := make([]zapcore.Field, 0, len(fields)+len(l.contextFields)+1)
	allFields = append(allFields, l.contextFields...)
	allFields = append(allFields, fields...)
	
	if err != nil {
		allFields = append(allFields, zap.Error(err))
	}

	l.zap.Fatal(msg, allFields...)
}

// APIRequest logs an API request
func (l *Logger) APIRequest(ctx context.Context, method, path string, status int, duration time.Duration) {
	if l == nil {
		return
	}

	l.Info("API Request",
		zap.String("method", method),
		zap.String("path", path),
		zap.Int("status", status),
		zap.Duration("duration", duration),
	)
}

// DBQuery logs a database query
func (l *Logger) DBQuery(ctx context.Context, operation, table string, duration time.Duration, err error) {
	if l == nil {
		return
	}

	fields := []zapcore.Field{
		zap.String("operation", operation),
		zap.String("table", table),
		zap.Duration("duration", duration),
	}

	if err != nil {
		l.Error("Database query failed", err, fields...)
		
		// Record metric
		if l.metrics != nil {
			l.metrics.RecordDatabaseQuery(operation, table, duration)
			l.metrics.RecordError("database", table)
		}
		
		return
	}

	l.Debug("Database query", fields...)
	
	// Record metric
	if l.metrics != nil {
		l.metrics.RecordDatabaseQuery(operation, table, duration)
	}
}

// ThirdPartyRequest logs a third-party API request
func (l *Logger) ThirdPartyRequest(ctx context.Context, service, endpoint string, status int, duration time.Duration, err error) {
	if l == nil {
		return
	}

	fields := []zapcore.Field{
		zap.String("service", service),
		zap.String("endpoint", endpoint),
		zap.Int("status", status),
		zap.Duration("duration", duration),
	}

	// Record metric
	if l.metrics != nil {
		statusStr := "success"
		if err != nil {
			statusStr = "error"
		}
		l.metrics.RecordThirdPartyRequest(service, statusStr)
	}

	if err != nil {
		l.Error("Third-party request failed", err, fields...)
		return
	}

	l.Debug("Third-party request", fields...)
}

// JobProcessed logs a processed job
func (l *Logger) JobProcessed(ctx context.Context, jobType, jobID string, duration time.Duration, err error) {
	if l == nil {
		return
	}

	fields := []zapcore.Field{
		zap.String("job_type", jobType),
		zap.String("job_id", jobID),
		zap.Duration("duration", duration),
	}

	// Record metric
	if l.metrics != nil {
		status := "success"
		if err != nil {
			status = "error"
		}
		l.metrics.RecordJobProcessed(jobType, status)
	}

	if err != nil {
		l.Error("Job processing failed", err, fields...)
		return
	}

	l.Info("Job processed", fields...)
}

// Shutdown closes the logger
func (l *Logger) Shutdown() error {
	if l == nil {
		return nil
	}

	return l.zap.Sync()
}

// mergeFields merges context fields with provided fields
func (l *Logger) mergeFields(fields []zapcore.Field) []zapcore.Field {
	if len(l.contextFields) == 0 {
		return fields
	}

	allFields := make([]zapcore.Field, 0, len(fields)+len(l.contextFields))
	allFields = append(allFields, l.contextFields...)
	allFields = append(allFields, fields...)

	return allFields
} 