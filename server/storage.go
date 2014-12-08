package server

type ClientStorage interface {
	FindClientByClientId(clientId string) (*Client, error)
	FindByClientIdAndSecret(clientId string, clientSecret string) (*Client, error)
}

type OwnerStorage interface {
	FindByOwnerUsername(username string) (*Owner, error)
	FindByOwnerUsernameAndPassword(username string, password string) (*Owner, error)
}

type SessionStorage interface {
	FindByAccessToken(accessToken string) (*Session, error)
	FindByRefreshToken(refreshToken string) (*Session, error)
	Save(session *Session)
	Delete(session *Session)
}
