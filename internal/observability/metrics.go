package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all the prometheus metrics for the application
type Metrics struct {
	httpRequestsTotal      *prometheus.CounterVec
	httpRequestDuration    *prometheus.HistogramVec
	databaseQueryDuration  *prometheus.HistogramVec
	activeSessions         prometheus.Gauge
	errorTotal             *prometheus.CounterVec
	activeSubscriptions    prometheus.Gauge
	paymentProcessedTotal  *prometheus.CounterVec
	cacheHitRatio          prometheus.Gauge
	jobQueueSize           prometheus.GaugeFunc
	jobProcessedTotal      *prometheus.CounterVec
	thirdPartyRequestTotal *prometheus.CounterVec
}

// Config holds configuration for metrics
type Config struct {
	Enabled          bool
	MetricsNamespace string
}

// DefaultConfig returns a default configuration for metrics
func DefaultConfig() *Config {
	return &Config{
		Enabled:          true,
		MetricsNamespace: "gobackend",
	}
}

// New creates a new metrics instance
func New(cfg *Config) *Metrics {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if !cfg.Enabled {
		return nil
	}

	m := &Metrics{
		httpRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status"},
		),
		httpRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "http_request_duration_seconds",
				Help:      "Duration of HTTP requests in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		databaseQueryDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "database_query_duration_seconds",
				Help:      "Duration of database queries in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation", "table"},
		),
		activeSessions: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "active_sessions",
				Help:      "Number of active sessions",
			},
		),
		errorTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "errors_total",
				Help:      "Total number of errors",
			},
			[]string{"type", "service"},
		),
		activeSubscriptions: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "active_subscriptions",
				Help:      "Number of active subscriptions",
			},
		),
		paymentProcessedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "payments_processed_total",
				Help:      "Total number of processed payments",
			},
			[]string{"status", "provider"},
		),
		cacheHitRatio: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "cache_hit_ratio",
				Help:      "Cache hit ratio (0.0-1.0)",
			},
		),
		thirdPartyRequestTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: cfg.MetricsNamespace,
				Name:      "third_party_requests_total",
				Help:      "Total number of third-party API requests",
			},
			[]string{"service", "status"},
		),
	}

	return m
}

// InstrumentHandler creates a middleware that records request metrics
func (m *Metrics) InstrumentHandler(next http.Handler) http.Handler {
	if m == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer that captures the status code
		rw := NewResponseWriter(w)
		
		// Execute the handler
		next.ServeHTTP(rw, r)
		
		// Record metrics
		duration := time.Since(start).Seconds()
		endpoint := r.URL.Path
		method := r.Method
		status := rw.Status()
		
		m.httpRequestsTotal.WithLabelValues(method, endpoint, string(rune(status))).Inc()
		m.httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration)
	})
}

// ResponseWriter wraps http.ResponseWriter to capture the status code
type ResponseWriter struct {
	http.ResponseWriter
	status int
}

// NewResponseWriter creates a new response writer
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

// WriteHeader captures the status code
func (rw *ResponseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Status returns the status code
func (rw *ResponseWriter) Status() int {
	return rw.status
}

// RecordDatabaseQuery records a database query
func (m *Metrics) RecordDatabaseQuery(operation, table string, duration time.Duration) {
	if m == nil {
		return
	}
	
	m.databaseQueryDuration.WithLabelValues(operation, table).Observe(duration.Seconds())
}

// RecordError increments the error counter
func (m *Metrics) RecordError(errorType, service string) {
	if m == nil {
		return
	}
	
	m.errorTotal.WithLabelValues(errorType, service).Inc()
}

// SetActiveSessions sets the number of active sessions
func (m *Metrics) SetActiveSessions(count int) {
	if m == nil {
		return
	}
	
	m.activeSessions.Set(float64(count))
}

// SetActiveSubscriptions sets the number of active subscriptions
func (m *Metrics) SetActiveSubscriptions(count int) {
	if m == nil {
		return
	}
	
	m.activeSubscriptions.Set(float64(count))
}

// RecordPaymentProcessed increments the payment processed counter
func (m *Metrics) RecordPaymentProcessed(status, provider string) {
	if m == nil {
		return
	}
	
	m.paymentProcessedTotal.WithLabelValues(status, provider).Inc()
}

// SetCacheHitRatio sets the cache hit ratio
func (m *Metrics) SetCacheHitRatio(ratio float64) {
	if m == nil {
		return
	}
	
	m.cacheHitRatio.Set(ratio)
}

// SetJobQueueSizeFunc sets the function to report job queue size
func (m *Metrics) SetJobQueueSizeFunc(f func() float64) {
	if m == nil {
		return
	}
	
	m.jobQueueSize = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "gobackend",
			Name:      "job_queue_size",
			Help:      "Current size of the job queue",
		},
		f,
	)
}

// RecordJobProcessed increments the job processed counter
func (m *Metrics) RecordJobProcessed(jobType, status string) {
	if m == nil {
		return
	}
	
	if m.jobProcessedTotal == nil {
		m.jobProcessedTotal = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gobackend",
				Name:      "jobs_processed_total",
				Help:      "Total number of processed jobs",
			},
			[]string{"type", "status"},
		)
	}
	
	m.jobProcessedTotal.WithLabelValues(jobType, status).Inc()
}

// RecordThirdPartyRequest increments the third-party request counter
func (m *Metrics) RecordThirdPartyRequest(service, status string) {
	if m == nil {
		return
	}
	
	m.thirdPartyRequestTotal.WithLabelValues(service, status).Inc()
}

// Handler returns a handler for exposing metrics
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	
	return promhttp.Handler()
} 