package models

import (
	"fmt"
)

// ValidationError represents a validation error
type ValidationError struct {
	Message string
}

// Error returns the error message
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s", e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(message string) ValidationError {
	return ValidationError{
		Message: message,
	}
}
