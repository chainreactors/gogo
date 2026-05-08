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
