package thirdparty

import (
	"fmt"
	"gobackend/internal/config"
	"gobackend/internal/services/thirdparty/openrouter"
	"sync"
)

// Provider manages all third-party services
type Provider struct {
	config      *config.ThirdPartyConfig
	openRouter  *openrouter.Service
	initOnce    sync.Once
	initialized bool
}

// New creates a new third-party services provider
func New(cfg *config.ThirdPartyConfig) *Provider {
	return &Provider{
		config: cfg,
	}
}

// Initialize initializes all enabled third-party services
func (p *Provider) Initialize() error {
	var err error
	p.initOnce.Do(func() {
		// Initialize OpenRouter if enabled
		if p.config.OpenRouter.Enabled {
			if err = p.initOpenRouter(); err != nil {
				err = fmt.Errorf("failed to initialize OpenRouter: %w", err)
				return
			}
		}

		// Initialize other third-party services here as needed
		
		p.initialized = true
	})
	return err
}

// initOpenRouter initializes the OpenRouter service
func (p *Provider) initOpenRouter() error {
	var err error
	p.openRouter, err = openrouter.New(p.config.OpenRouter.ToServiceConfig())
	return err
}

// OpenRouter returns the OpenRouter service
// Returns nil if the service is not enabled or not initialized
func (p *Provider) OpenRouter() *openrouter.Service {
	if !p.initialized || !p.config.OpenRouter.Enabled {
		return nil
	}
	return p.openRouter
}

// IsInitialized returns whether the provider has been initialized
func (p *Provider) IsInitialized() bool {
	return p.initialized
} 