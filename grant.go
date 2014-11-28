package oauth2server


type GrantData struct {
	ClientID string
	UserID string
	Scope []string
	RefreshToken string
	AuthCode string
	ExtraData map[string]string
}

type Grant interface {
	ValidateGrantType(gt string, ctx *Ctx, c *Config, s Storage) *GrantData
	CreateAccessToken(config *Config, storage Storage, grantData *GrantData, scopes []string) (*AccessTokenResponse, error)
	Name() (string)
}
