package oauth2server

import (
	"fmt"
)

type ClientStorage interface {

	FindClientByClientId(clientId string) (*Client, error)
	FindByClientIdAndSecret(clientId string, clientSecret string) (*Client, error)
}

type OwnerStorage interface {

	FindByOwnerUsername(username string) (*Owner, error)
	FindByOwnerUsernameAndPassword(username string, password string) (*Owner, error)
}

type InMemoryOwnerClientStorage struct {

	ownersByUsername map[string]*Owner
	ownersByUsernameAndPassword map[string]*Owner
	clientsByClientId map[string]*Client
	clientsByClientIdAndSecret map[string]*Client
}

func (storage *InMemoryOwnerClientStorage) AddClient(clientId string, clientSecret string, client *Client) *InMemoryOwnerClientStorage {

	storage.clientsByClientId[clientId] = client
	storage.clientsByClientIdAndSecret[clientId + ":" + clientSecret] = client
	return storage
}
func (storage *InMemoryOwnerClientStorage) AddOwner(username string, password string, owner *Owner) *InMemoryOwnerClientStorage {

	storage.ownersByUsername[username] = owner
	storage.ownersByUsernameAndPassword[username + ":" + password] = owner
	return storage
}

func (storage *InMemoryOwnerClientStorage) FindClientByClientId(clientId string) (*Client, error) {

	client, ok := storage.clientsByClientId[clientId]

	if !ok {

		return nil, fmt.Errorf("couldnt find the client")
	}

	return client, nil
}

func (storage *InMemoryOwnerClientStorage) FindByClientIdAndSecret(clientId string, clientSecret string) (*Client, error) {

	client, ok := storage.clientsByClientIdAndSecret[clientId + ":" + clientSecret]

	if !ok {

		return nil, fmt.Errorf("couldnt find the client")
	}

	return client, nil
}
func (storage *InMemoryOwnerClientStorage) FindByOwnerUsername(username string) (*Owner, error) {

	owner, ok := storage.ownersByUsername[username]

	if !ok {

		return nil, fmt.Errorf("couldnt find the owner")
	}

	return owner, nil
}

func (storage *InMemoryOwnerClientStorage) FindByOwnerUsernameAndPassword(username string, password string) (*Owner, error) {

	owner, ok := storage.ownersByUsernameAndPassword[username + ":" + password]

	if !ok {

		return nil, fmt.Errorf("couldnt find the owner")
	}

	return owner, nil
}

func NewInMemoryOwnerClientStorage() *InMemoryOwnerClientStorage {

	return &InMemoryOwnerClientStorage{
		make(map[string]*Owner),
		make(map[string]*Owner),
		make(map[string]*Client),
		make(map[string]*Client),
	}
}

type SessionStorage interface {

	FindByAccessToken(accessToken string) (*Session, error)
	FindByRefreshToken(refreshToken string) (*Session, error)
	Save(session *Session)
	Delete(session *Session)
}

type InMemorySessionStorage struct {
	sessionsByAccessToken map[string]*Session
	sessionsByRefreshToken map[string]*Session
}

func (storage *InMemorySessionStorage) FindByAccessToken(accessToken string) (*Session, error) {

	session, ok := storage.sessionsByAccessToken[accessToken]

	if !ok {

		return nil, fmt.Errorf("Session for access token %q not found", accessToken)
	}

	return session, nil
}

func (storage *InMemorySessionStorage) FindByRefreshToken(refreshToken string) (*Session, error) {

	session, ok := storage.sessionsByRefreshToken[refreshToken]

	if !ok {

		return nil, fmt.Errorf("Session for refresh token %q not found", refreshToken)
	}

	return session, nil
}

func (storage *InMemorySessionStorage) Save(session *Session) {

	storage.sessionsByAccessToken[session.AccessToken.Token] = session

	if session.RefreshToken != nil {

		storage.sessionsByRefreshToken[session.RefreshToken.Token] = session
	}
}

func (storage *InMemorySessionStorage) Delete(session *Session) {

	delete(storage.sessionsByAccessToken, session.AccessToken.Token)
	delete(storage.sessionsByRefreshToken, session.RefreshToken.Token)
}


func NewInMemorySessionStorage() *InMemorySessionStorage {

	return &InMemorySessionStorage{
		make(map[string]*Session),
		make(map[string]*Session),
	}
}
