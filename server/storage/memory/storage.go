package memory

import (
	"github.com/yjv/goauth2-server/server"
	"fmt"
	"time"
)

type MemoryOwnerClientStorage struct {
	ownersByUsername            map[string]*server.Owner
	ownersByUsernameAndPassword map[string]*server.Owner
	clientsByClientId           map[string]*server.Client
	clientsByClientIdAndSecret  map[string]*server.Client
}

func (storage *MemoryOwnerClientStorage) AddClient(clientId string, clientSecret string, client *server.Client) *MemoryOwnerClientStorage {

	storage.clientsByClientId[clientId] = client
	storage.clientsByClientIdAndSecret[clientId+":"+clientSecret] = client
	return storage
}
func (storage *MemoryOwnerClientStorage) AddOwner(username string, password string, owner *server.Owner) *MemoryOwnerClientStorage {

	storage.ownersByUsername[username] = owner
	storage.ownersByUsernameAndPassword[username+":"+password] = owner
	return storage
}

func (storage *MemoryOwnerClientStorage) FindClientById(clientId string) (*server.Client, error) {

	client, ok := storage.clientsByClientId[clientId]

	if !ok {

		return nil, fmt.Errorf("couldnt find the client")
	}

	return client, nil
}

func (storage *MemoryOwnerClientStorage) FindClientByIdAndSecret(clientId string, clientSecret string) (*server.Client, error) {

	client, ok := storage.clientsByClientIdAndSecret[clientId+":"+clientSecret]

	if !ok {

		return nil, fmt.Errorf("couldnt find the client")
	}

	return client, nil
}

func (storage *MemoryOwnerClientStorage) RefreshClient(client *Client) (*Client, error) {

	client, exists := storage.clientsByClientId[client.Id]

	if !exists {

		return nil, fmt.Errorf("failed to refresh client")
	}

	return client, nil
}

func (storage *MemoryOwnerClientStorage) FindOwnerByUsername(username string) (*server.Owner, error) {

	owner, ok := storage.ownersByUsername[username]

	if !ok {

		return nil, fmt.Errorf("couldnt find the owner")
	}

	return owner, nil
}

func (storage *MemoryOwnerClientStorage) FindOwnerByUsernameAndPassword(username string, password string) (*server.Owner, error) {

	owner, ok := storage.ownersByUsernameAndPassword[username+":"+password]

	if !ok {

		return nil, fmt.Errorf("couldnt find the owner")
	}

	return owner, nil
}

func (storage *MemoryOwnerClientStorage) RefreshOwner(owner *Owner) (*Owner, error) {

	owner, exists := storage.ownersByUsername[owner.Id]

	if !exists {

		return nil, fmt.Errorf("failed to refresh owner")
	}

	return owner, nil
}

func NewMemoryOwnerClientStorage() *MemoryOwnerClientStorage {

	return &MemoryOwnerClientStorage{
		make(map[string]*server.Owner),
		make(map[string]*server.Owner),
		make(map[string]*server.Client),
		make(map[string]*server.Client),
	}
}

type MemorySessionStorage struct {
	sessionsByAccessToken  map[string]*server.Session
	sessionsByRefreshToken map[string]*server.Session
}

func (storage *MemorySessionStorage) FindSessionByAccessToken(accessToken string) (*server.Session, error) {

	session, ok := storage.sessionsByAccessToken[accessToken]

	if !ok {

		return nil, fmt.Errorf("Session not found")
	}

	if storage.isExpired(session.AccessToken) {

		if storage.isExpired(session.RefreshToken) {

			go storage.Delete(session)
		}

		return nil, fmt.Errorf("Refresh token is expired")
	}

	return session, nil
}

func (storage *MemorySessionStorage) FindSessionByRefreshToken(refreshToken string) (*server.Session, error) {

	session, ok := storage.sessionsByRefreshToken[refreshToken]

	if !ok {

		return nil, fmt.Errorf("Session for refresh token %q not found", refreshToken)
	}

	if storage.isExpired(session.RefreshToken) {

		go storage.Delete(session)
		return nil, fmt.Errorf("Refresh token is expired")
	}

	return session, nil
}

func (storage *MemorySessionStorage) SaveSession(session *server.Session) {

	storage.sessionsByAccessToken[session.AccessToken.Token] = session

	if session.RefreshToken != nil {

		storage.sessionsByRefreshToken[session.RefreshToken.Token] = session
	}
}

func (storage *MemorySessionStorage) DeleteSession(session *server.Session) {

	delete(storage.sessionsByAccessToken, session.AccessToken.Token)
	delete(storage.sessionsByRefreshToken, session.RefreshToken.Token)
}

func (storage *MemorySessionStorage) isExpired(token *server.Token) bool {

	return token == nil || (token.Expires != server.NoExpiration && token.Expires < time.Now().UTC().Unix())
}

func NewMemorySessionStorage() *MemorySessionStorage {

	return &MemorySessionStorage{
		make(map[string]*server.Session),
		make(map[string]*server.Session),
	}
}
