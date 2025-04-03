package security

// Security event types
type EventType string

const (
	// EventAuth represents authentication-related events
	EventAuth EventType = "AUTH"

	// EventAccess represents access control events
	EventAccess EventType = "ACCESS"

	// EventData represents data security events
	EventData EventType = "DATA"

	// EventSystem represents system security events
	EventSystem EventType = "SYSTEM"

	// EventAPI represents API security events
	EventAPI EventType = "API"
)

// Event severity levels
type SeverityLevel string

const (
	// LevelCritical is for events requiring immediate attention
	LevelCritical SeverityLevel = "CRITICAL"

	// LevelHigh is for significant security events
	LevelHigh SeverityLevel = "HIGH"

	// LevelMedium is for moderate security concerns
	LevelMedium SeverityLevel = "MEDIUM"

	// LevelLow is for minor security events
	LevelLow SeverityLevel = "LOW"

	// LevelInfo is for informational security events
	LevelInfo SeverityLevel = "INFO"
)

// Common HTTP headers
const (
	HeaderXForwardedFor       = "X-Forwarded-For"
	HeaderXRealIP             = "X-Real-IP"
	HeaderXRequestID          = "X-Request-ID"
	HeaderXContentTypeOptions = "X-Content-Type-Options"
	HeaderXFrameOptions       = "X-Frame-Options"
	HeaderXXSSProtection      = "X-XSS-Protection"
	HeaderReferrerPolicy      = "Referrer-Policy"
	HeaderPermissionsPolicy   = "Permissions-Policy"
	HeaderCacheControl        = "Cache-Control"
)

// HTTP security options
const (
	OptionNoCache         = "no-store, max-age=0"
	OptionNoSniff         = "nosniff"
	OptionFrameDeny       = "DENY"
	OptionFrameSameOrigin = "SAMEORIGIN"
	OptionXSSModeBlock    = "1; mode=block"
)

// Context keys for security information
type ContextKey string

const (
	ContextKeyUserID      ContextKey = "user_id"
	ContextKeyTenantID    ContextKey = "tenant_id"
	ContextKeyRequestID   ContextKey = "request_id"
	ContextKeyIPAddress   ContextKey = "ip_address"
	ContextKeyUserAgent   ContextKey = "user_agent"
	ContextKeyRoles       ContextKey = "roles"
	ContextKeyPermissions ContextKey = "permissions"
	ContextKeySessionID   ContextKey = "session_id"
)

// Security error messages
const (
	ErrMsgUnauthorized        = "unauthorized access attempt"
	ErrMsgForbidden           = "access forbidden"
	ErrMsgRateLimitExceeded   = "rate limit exceeded"
	ErrMsgTokenExpired        = "token expired"
	ErrMsgInvalidToken        = "invalid token"
	ErrMsgMissingPermission   = "missing required permission"
	ErrMsgInvalidCredentials  = "invalid credentials"
	ErrMsgAccountLocked       = "account is locked"
	ErrMsgInsufficientEntropy = "password doesn't meet security requirements"
	ErrMsgSuspiciousActivity  = "suspicious activity detected"
	ErrMsgCrossTenantAccess   = "cross-tenant access attempt"
	ErrMsgDataLeakage         = "potential data leakage detected"
)

// IP-related constants
const (
	PrivateNetworkCIDR_10    = "10.0.0.0/8"
	PrivateNetworkCIDR_172   = "172.16.0.0/12"
	PrivateNetworkCIDR_192   = "192.168.0.0/16"
	PrivateNetworkCIDR_Local = "127.0.0.0/8"
)
