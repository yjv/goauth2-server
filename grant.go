package oauth2server


type Grant interface {
	CreateAccessToken(accessTokenRequest *AccessTokenRequest) (*AccessToken, error, bool)
	Name() string
}

type TokenIdGenerate interface {

	GenerateTokenId() string
}
