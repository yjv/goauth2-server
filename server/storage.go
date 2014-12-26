package server

type ClientStorage interface {
	FindClientById(clientId string) (*Client, error)
	FindClientByIdAndSecret(clientId string, clientSecret string) (*Client, error)
	RefreshClient(client *Client) (*Client, error)
}

type OwnerStorage interface {
	FindOwnerByUsername(username string) (*Owner, error)
	FindOwnerByUsernameAndPassword(username string, password string) (*Owner, error)
	RefreshOwner(owner *Owner) (*Owner, error)
}

type SessionStorage interface {
	FindSessionByAccessToken(accessToken string) (*Session, error)
	FindSessionByRefreshToken(refreshToken string) (*Session, error)
	SaveSession(session *Session)
	DeleteSession(session *Session)
}

type ScopeStorage interface {
	FindScopeByName(name string) (*Scope, error)
}
