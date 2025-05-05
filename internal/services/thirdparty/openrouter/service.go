package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds the configuration for the OpenRouter service
type Config struct {
	APIKey           string
	BaseURL          string
	AppName          string
	AppURL           string
	TimeoutSeconds   int
	RetryAttempts    int
	RetryWaitSeconds int
}

// Service provides methods to interact with the OpenRouter API
type Service struct {
	config     Config
	httpClient *http.Client
}

// New creates a new OpenRouter service
func New(config Config) (*Service, error) {
	if config.APIKey == "" {
		return nil, errors.New("openrouter API key is required")
	}

	if config.BaseURL == "" {
		config.BaseURL = "https://openrouter.ai/api/v1"
	}

	if config.TimeoutSeconds <= 0 {
		config.TimeoutSeconds = 30
	}

	if config.RetryAttempts <= 0 {
		config.RetryAttempts = 3
	}

	if config.RetryWaitSeconds <= 0 {
		config.RetryWaitSeconds = 1
	}

	client := &http.Client{
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}

	return &Service{
		config:     config,
		httpClient: client,
	}, nil
}

// Tool represents a function that can be called by the model
type Tool struct {
	Type       string                 `json:"type"`
	Function   FunctionDefinition     `json:"function"`
	ID         string                 `json:"id,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// FunctionDefinition defines a function that can be called by the model
type FunctionDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ResponseFormat defines how the model response should be structured
type ResponseFormat struct {
	Type       string                `json:"type"`
	JSONSchema *JSONSchemaDefinition `json:"schema,omitempty"`
}

// JSONSchemaDefinition defines a JSON schema for structured outputs
type JSONSchemaDefinition struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

// Content represents the content of a message which may include text or multimedia
type Content struct {
	Type     string `json:"type,omitempty"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

// ChatCompletionRequest represents the request structure for chat completions
type ChatCompletionRequest struct {
	Model            string                  `json:"model"`
	Messages         []ChatCompletionMessage `json:"messages"`
	Temperature      float64                 `json:"temperature,omitempty"`
	MaxTokens        int                     `json:"max_tokens,omitempty"`
	Stream           bool                    `json:"stream,omitempty"`
	TopP             float64                 `json:"top_p,omitempty"`
	FrequencyPenalty float64                 `json:"frequency_penalty,omitempty"`
	PresencePenalty  float64                 `json:"presence_penalty,omitempty"`
	Tools            []Tool                  `json:"tools,omitempty"`
	ToolChoice       interface{}             `json:"tool_choice,omitempty"`
	ResponseFormat   *ResponseFormat         `json:"response_format,omitempty"`
	User             string                  `json:"user,omitempty"`
}

// ChatCompletionMessage represents a single message in the conversation
type ChatCompletionMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
	Name    string      `json:"name,omitempty"`
}

// ChatCompletionResponse represents the response from the chat completions API
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Model   string   `json:"model"`
	Created int64    `json:"created"`
	Usage   Usage    `json:"usage"`
	Choices []Choice `json:"choices"`
	Error   *Error   `json:"error,omitempty"`
}

// Usage represents token usage information
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Choice represents a completion choice
type Choice struct {
	Index        int                   `json:"index"`
	Message      ChatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
	ToolCalls    []ToolCall            `json:"tool_calls,omitempty"`
}

// ToolCall represents a call to a function made by the model
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Error represents an API error
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// Error implements the error interface
func (e *Error) Error() string {
	return e.Message
}

// CreateChatCompletion sends a chat completion request to the OpenRouter API
func (s *Service) CreateChatCompletion(ctx context.Context, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	endpoint := fmt.Sprintf("%s/chat/completions", s.config.BaseURL)

	requestBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	return s.sendRequest(ctx, endpoint, requestBody)
}

// sendRequest sends a request to the OpenRouter API with retry logic
func (s *Service) sendRequest(ctx context.Context, endpoint string, requestBody []byte) (*ChatCompletionResponse, error) {
	var lastErr error

	for attempt := 0; attempt < s.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(s.config.RetryWaitSeconds) * time.Second):
				// Wait before retrying
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(requestBody))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.config.APIKey))

		// Add OpenRouter-specific headers
		if s.config.AppURL != "" {
			req.Header.Set("HTTP-Referer", s.config.AppURL)
		}
		if s.config.AppName != "" {
			req.Header.Set("X-Title", s.config.AppName)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("API error: status code %d, body: %s", resp.StatusCode, string(body))

			// Only retry on server errors and rate limits
			if resp.StatusCode < 500 && resp.StatusCode != 429 {
				return nil, lastErr
			}
			continue
		}

		var result ChatCompletionResponse
		if err := json.Unmarshal(body, &result); err != nil {
			lastErr = fmt.Errorf("failed to unmarshal response: %w", err)
			continue
		}

		if result.Error != nil {
			return &result, fmt.Errorf("API returned error: %s", result.Error.Message)
		}

		return &result, nil
	}

	return nil, fmt.Errorf("max retry attempts reached: %w", lastErr)
}
