package pkg

import "sync"

// ResourceProvider supplies template/config bytes by logical name.
type ResourceProvider func(string) []byte

var resourceProvider struct {
	sync.RWMutex
	fn ResourceProvider
}

// SetResourceProvider installs an external template/config provider.
func SetResourceProvider(provider ResourceProvider) {
	resourceProvider.Lock()
	defer resourceProvider.Unlock()
	resourceProvider.fn = provider
}

// ResetResourceProvider removes the external template/config provider.
func ResetResourceProvider() {
	SetResourceProvider(nil)
}

// ResourceLoader is called by runner.Init to load all resources (ports, fingers,
// extractors, neutron templates). When nil, the default loading from ResourceProvider
// is used. Set to a no-op when the SDK engine has already injected resources.
var resourceLoader struct {
	sync.RWMutex
	fn func() error
}

// SetResourceLoader overrides the default resource loading strategy.
// Pass nil to restore default behavior.
func SetResourceLoader(fn func() error) {
	resourceLoader.Lock()
	defer resourceLoader.Unlock()
	resourceLoader.fn = fn
}

// LoadResources executes the configured resource loader. Returns nil immediately
// if an external loader was set (e.g. SDK already loaded resources).
func LoadResources() error {
	resourceLoader.RLock()
	fn := resourceLoader.fn
	resourceLoader.RUnlock()
	if fn != nil {
		return fn()
	}
	return defaultLoadResources()
}

func defaultLoadResources() error {
	if err := LoadPortConfig(""); err != nil {
		return err
	}
	if err := LoadFinger(nil); err != nil {
		return err
	}
	if err := LoadExtractor(); err != nil {
		return err
	}
	return nil
}

// LoadEmbeddedConfig loads the standalone embedded config without consulting
// an installed external provider.
func LoadEmbeddedConfig(typ string) []byte {
	return loadEmbeddedConfig(typ)
}

// LoadConfig loads config bytes from the external provider first, then from
// the embedded templates kept for standalone gogo compatibility.
func LoadConfig(typ string) []byte {
	resourceProvider.RLock()
	provider := resourceProvider.fn
	resourceProvider.RUnlock()
	if provider != nil {
		if data := provider(typ); len(data) > 0 {
			return data
		}
	}
	return loadEmbeddedConfig(typ)
}
