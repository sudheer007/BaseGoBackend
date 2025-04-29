package api

import (
	"gobackend/internal/observability"

	"github.com/gin-gonic/gin"
)

// RegisterMetricsRoute registers a route for exposing metrics
func RegisterMetricsRoute(r *gin.Engine, metrics *observability.Metrics) {
	// Skip if metrics is nil
	if metrics == nil {
		return
	}

	// Register metrics endpoint
	r.GET("/metrics", gin.WrapH(metrics.Handler()))
} 