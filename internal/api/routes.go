package api

import (
	"gobackend/internal/api/ai"
	"gobackend/internal/middleware"
	"gobackend/internal/services/thirdparty"

	"github.com/gin-gonic/gin"
)

// RegisterAIRoutes registers AI-related routes
func RegisterAIRoutes(engine *gin.Engine, thirdPartyProvider *thirdparty.Provider, authMiddleware *middleware.AuthMiddleware) {
	// Create AI handler
	aiHandler := ai.NewHandler(thirdPartyProvider)

	// Create API v1 group
	v1 := engine.Group("/api/v1")

	// Create AI routes group with authentication
	aiGroup := v1.Group("/ai")
	aiGroup.Use(authMiddleware.Authenticate())

	// Register AI routes
	aiGroup.POST("/chat-completion", aiHandler.HandleChatCompletion)
}
