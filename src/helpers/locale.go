package helpers

import (
	"sync"
)

// Locale helper struct to manage localization
type Locale struct {
	mu     sync.RWMutex
	locale string
}

// Singleton instance of Locale
var instance *Locale
var once sync.Once

// GetInstance returns the singleton instance of Locale
func GetInstance() *Locale {
	once.Do(func() {
		instance = &Locale{}
	})
	return instance
}

// GetLocale retrieves the current application locale
func (l *Locale) GetLocale() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.locale
}

// SetLocale sets the application locale
func (l *Locale) SetLocale(locale string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locale = locale
}
