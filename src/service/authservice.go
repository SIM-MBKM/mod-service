package service

// AuthService extends Service with additional behavior.
type AuthService struct {
	Service *Service
}

// NewAuthService creates a new instance of AuthService.
func NewAuthService(baseURI string, asyncURIs []string) *AuthService {
	return &AuthService{
		Service: NewService(baseURI, asyncURIs),
	}
}
