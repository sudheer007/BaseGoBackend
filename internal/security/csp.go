package security

import (
	"fmt"
	"strings"
)

// CSPConfig defines a Content Security Policy configuration
type CSPConfig struct {
	DefaultSrc      []string
	ScriptSrc       []string
	StyleSrc        []string
	ImgSrc          []string
	ConnectSrc      []string
	FontSrc         []string
	ObjectSrc       []string
	MediaSrc        []string
	FrameSrc        []string
	ReportURI       string
	UpgradeInsecReq bool
	ReportOnly      bool
}

// DefaultCSPConfig returns a secure default CSP configuration
func DefaultCSPConfig() *CSPConfig {
	return &CSPConfig{
		DefaultSrc:      []string{"'self'"},
		ScriptSrc:       []string{"'self'", "'unsafe-inline'", "'unsafe-eval'"},
		StyleSrc:        []string{"'self'", "'unsafe-inline'"},
		ImgSrc:          []string{"'self'", "data:"},
		ConnectSrc:      []string{"'self'"},
		FontSrc:         []string{"'self'"},
		ObjectSrc:       []string{"'none'"},
		MediaSrc:        []string{"'self'"},
		FrameSrc:        []string{"'self'"},
		UpgradeInsecReq: true,
		ReportOnly:      false,
	}
}

// StrictCSPConfig returns a very strict CSP configuration
func StrictCSPConfig() *CSPConfig {
	return &CSPConfig{
		DefaultSrc:      []string{"'self'"},
		ScriptSrc:       []string{"'self'"},
		StyleSrc:        []string{"'self'"},
		ImgSrc:          []string{"'self'"},
		ConnectSrc:      []string{"'self'"},
		FontSrc:         []string{"'self'"},
		ObjectSrc:       []string{"'none'"},
		MediaSrc:        []string{"'self'"},
		FrameSrc:        []string{"'none'"},
		UpgradeInsecReq: true,
		ReportOnly:      false,
	}
}

// BuildPolicy builds the Content-Security-Policy header value
func (c *CSPConfig) BuildPolicy() string {
	policies := []string{}

	if len(c.DefaultSrc) > 0 {
		policies = append(policies, fmt.Sprintf("default-src %s", strings.Join(c.DefaultSrc, " ")))
	}

	if len(c.ScriptSrc) > 0 {
		policies = append(policies, fmt.Sprintf("script-src %s", strings.Join(c.ScriptSrc, " ")))
	}

	if len(c.StyleSrc) > 0 {
		policies = append(policies, fmt.Sprintf("style-src %s", strings.Join(c.StyleSrc, " ")))
	}

	if len(c.ImgSrc) > 0 {
		policies = append(policies, fmt.Sprintf("img-src %s", strings.Join(c.ImgSrc, " ")))
	}

	if len(c.ConnectSrc) > 0 {
		policies = append(policies, fmt.Sprintf("connect-src %s", strings.Join(c.ConnectSrc, " ")))
	}

	if len(c.FontSrc) > 0 {
		policies = append(policies, fmt.Sprintf("font-src %s", strings.Join(c.FontSrc, " ")))
	}

	if len(c.ObjectSrc) > 0 {
		policies = append(policies, fmt.Sprintf("object-src %s", strings.Join(c.ObjectSrc, " ")))
	}

	if len(c.MediaSrc) > 0 {
		policies = append(policies, fmt.Sprintf("media-src %s", strings.Join(c.MediaSrc, " ")))
	}

	if len(c.FrameSrc) > 0 {
		policies = append(policies, fmt.Sprintf("frame-src %s", strings.Join(c.FrameSrc, " ")))
	}

	if c.ReportURI != "" {
		policies = append(policies, fmt.Sprintf("report-uri %s", c.ReportURI))
	}

	if c.UpgradeInsecReq {
		policies = append(policies, "upgrade-insecure-requests")
	}

	return strings.Join(policies, "; ")
}

// HeaderName returns the appropriate header name based on the configuration
func (c *CSPConfig) HeaderName() string {
	if c.ReportOnly {
		return "Content-Security-Policy-Report-Only"
	}
	return "Content-Security-Policy"
}
