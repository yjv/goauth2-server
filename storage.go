package oauth2server

type ClientStorage interface {

	FindClientByClientId(clientId string) (*Client, error)
	FindByClientIdAndSecret(clientId string, clientSecret string) (*Client, error)
}

type OwnerStorage interface {

	FindByOwnerId(ownerId string)
}

type OwnerCredentialsVerifier interface {

	VerifyOwnerCredentials(username string, password string) (string, error)
}

type SessionStorage interface {

	FindByAccessToken(accessToken *AccessToken) (*Session, error)
	FindByRefreshToken(refreshToken *RefreshToken) (*Session, error)
}
