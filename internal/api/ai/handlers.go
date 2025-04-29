package ai

import (
	"errors"
	"gobackend/internal/services/thirdparty"
	"gobackend/internal/services/thirdparty/openrouter"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler holds handlers for AI-related functionality
type Handler struct {
	thirdPartyProvider *thirdparty.Provider
}

// NewHandler creates a new AI handler
func NewHandler(provider *thirdparty.Provider) *Handler {
	return &Handler{
		thirdPartyProvider: provider,
	}
}

// ChatCompletionRequest defines the request structure for chat completions
type ChatCompletionRequest struct {
	Model            string                             `json:"model" binding:"required"`
	Messages         []openrouter.ChatCompletionMessage `json:"messages" binding:"required,min=1"`
	Temperature      float64                            `json:"temperature,omitempty"`
	MaxTokens        int                                `json:"max_tokens,omitempty"`
	Stream           bool                               `json:"stream,omitempty"`
	TopP             float64                            `json:"top_p,omitempty"`
	FrequencyPenalty float64                            `json:"frequency_penalty,omitempty"`
	PresencePenalty  float64                            `json:"presence_penalty,omitempty"`
	Tools            []openrouter.Tool                  `json:"tools,omitempty"`
	ToolChoice       interface{}                        `json:"tool_choice,omitempty"`
	ResponseFormat   *openrouter.ResponseFormat         `json:"response_format,omitempty"`
	User             string                             `json:"user,omitempty"`
}

// ChatCompletionResponse defines the response structure for chat completions
type ChatCompletionResponse struct {
	ID        string      `json:"id,omitempty"`
	Model     string      `json:"model,omitempty"`
	Created   int64       `json:"created,omitempty"`
	Content   interface{} `json:"content,omitempty"`
	Usage     *Usage      `json:"usage,omitempty"`
	ToolCalls interface{} `json:"tool_calls,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// Usage represents token usage information in the response
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// HandleChatCompletion handles chat completion requests
func (h *Handler) HandleChatCompletion(c *gin.Context) {
	// Check if OpenRouter service is available
	openRouterService := h.thirdPartyProvider.OpenRouter()
	if openRouterService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "AI service is not available",
		})
		return
	}

	// Parse request
	var req ChatCompletionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format: " + err.Error(),
		})
		return
	}

	// Create OpenRouter request
	openRouterReq := openrouter.ChatCompletionRequest{
		Model:            req.Model,
		Messages:         req.Messages,
		Temperature:      req.Temperature,
		MaxTokens:        req.MaxTokens,
		Stream:           req.Stream,
		TopP:             req.TopP,
		FrequencyPenalty: req.FrequencyPenalty,
		PresencePenalty:  req.PresencePenalty,
		Tools:            req.Tools,
		ToolChoice:       req.ToolChoice,
		ResponseFormat:   req.ResponseFormat,
		User:             req.User,
	}

	// Call OpenRouter service
	response, err := openRouterService.CreateChatCompletion(c.Request.Context(), openRouterReq)
	if err != nil {
		statusCode := http.StatusInternalServerError
		errorMessage := "Failed to generate completion"

		// Check for specific error types
		var apiError *openrouter.Error
		if errors.As(err, &apiError) {
			if apiError.Code == "rate_limit_exceeded" {
				statusCode = http.StatusTooManyRequests
				errorMessage = "Rate limit exceeded"
			} else if apiError.Code == "invalid_api_key" {
				statusCode = http.StatusUnauthorized
				errorMessage = "Authentication failed"
			}
		}

		c.JSON(statusCode, gin.H{
			"error": errorMessage,
		})
		return
	}

	// Create response
	chatResponse := ChatCompletionResponse{
		ID:      response.ID,
		Model:   response.Model,
		Created: response.Created,
		Usage: &Usage{
			PromptTokens:     response.Usage.PromptTokens,
			CompletionTokens: response.Usage.CompletionTokens,
			TotalTokens:      response.Usage.TotalTokens,
		},
	}

	// Check if response has choices
	if len(response.Choices) > 0 {
		chatResponse.Content = response.Choices[0].Message.Content

		// Include tool calls if present
		if len(response.Choices[0].ToolCalls) > 0 {
			chatResponse.ToolCalls = response.Choices[0].ToolCalls
		}
	}

	// Return response
	c.JSON(http.StatusOK, chatResponse)
}

// HandleStreamChatCompletion handles streaming chat completion requests
func (h *Handler) HandleStreamChatCompletion(c *gin.Context) {
	// Implementation for streaming responses
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "Streaming is not yet implemented",
	})
}
