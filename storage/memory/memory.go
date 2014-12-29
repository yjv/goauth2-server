package memory

import (
	"fmt"
	"github.com/yjv/goauth2-server/server"
	"time"
)

type OwnerClientStorage struct {
	ownersByUsername            map[string]*server.Owner
	ownersByUsernameAndPassword map[string]*server.Owner
	clientsByClientId           map[string]*server.Client
	clientsByClientIdAndSecret  map[string]*server.Client
}

func (storage *OwnerClientStorage) AddClient(clientId string, clientSecret string, client *server.Client) *OwnerClientStorage {

	storage.clientsByClientId[clientId] = client
	storage.clientsByClientIdAndSecret[clientId+":"+clientSecret] = client
	return storage
}
func (storage *OwnerClientStorage) AddOwner(username string, password string, owner *server.Owner) *OwnerClientStorage {

	storage.ownersByUsername[username] = owner
	storage.ownersByUsernameAndPassword[username+":"+password] = owner
	return storage
}

func (storage *OwnerClientStorage) FindClientById(clientId string) (*server.Client, error) {

	client, ok := storage.clientsByClientId[clientId]

	if !ok {

		return nil, fmt.Errorf("couldnt find the client with id %s", clientId)
	}

	return client, nil
}

func (storage *OwnerClientStorage) FindClientByIdAndSecret(clientId string, clientSecret string) (*server.Client, error) {

	client, ok := storage.clientsByClientIdAndSecret[clientId+":"+clientSecret]

	if !ok {

		return nil, fmt.Errorf("couldnt find the client with id %s and secret", clientId)
	}

	return client, nil
}

func (storage *OwnerClientStorage) RefreshClient(client *server.Client) (*server.Client, error) {

	client, exists := storage.clientsByClientId[client.Id]

	if !exists {

		return nil, fmt.Errorf("failed to refresh client with id %s", client.Id)
	}

	return client, nil
}

func (storage *OwnerClientStorage) FindOwnerByUsername(username string) (*server.Owner, error) {

	owner, ok := storage.ownersByUsername[username]

	if !ok {

		return nil, fmt.Errorf("couldnt find the owner by username %s", username)
	}

	return owner, nil
}

func (storage *OwnerClientStorage) FindOwnerByUsernameAndPassword(username string, password string) (*server.Owner, error) {

	owner, ok := storage.ownersByUsernameAndPassword[username+":"+password]

	if !ok {

		return nil, fmt.Errorf("couldnt find the owner by username %s and password", username)
	}

	return owner, nil
}

func (storage *OwnerClientStorage) RefreshOwner(owner *server.Owner) (*server.Owner, error) {

	owner, exists := storage.ownersByUsername[owner.Id]

	if !exists {

		return nil, fmt.Errorf("failed to refresh owner with id %s", owner.Id)
	}

	return owner, nil
}

func NewOwnerClientStorage() *OwnerClientStorage {

	return &OwnerClientStorage{
		make(map[string]*server.Owner),
		make(map[string]*server.Owner),
		make(map[string]*server.Client),
		make(map[string]*server.Client),
	}
}

type SessionStorage struct {
	sessionsByAccessToken  map[string]*server.Session
	sessionsByRefreshToken map[string]*server.Session
}

func (storage *SessionStorage) FindSessionByAccessToken(accessToken string) (*server.Session, error) {

	session, ok := storage.sessionsByAccessToken[accessToken]

	if !ok {

		return nil, fmt.Errorf("Session not found for access token ending in %s", accessToken[len(accessToken)-5:])
	}

	if storage.isExpired(session.AccessToken) {

		if storage.isExpired(session.RefreshToken) {

			go storage.DeleteSession(session)
		}

		return nil, fmt.Errorf("Refresh token ending in %s is expired", session.RefreshToken[len(session.RefreshToken)-5:])
	}

	return session, nil
}

func (storage *SessionStorage) FindSessionByRefreshToken(refreshToken string) (*server.Session, error) {

	session, ok := storage.sessionsByRefreshToken[refreshToken]

	if !ok {

		return nil, fmt.Errorf("Session for refresh token ending in %q not found", refreshToken[len(refreshToken)-5:])
	}

	if storage.isExpired(session.RefreshToken) {

		go storage.DeleteSession(session)
		return nil, fmt.Errorf("Refresh token ending in %s is expired", session.RefreshToken[len(session.RefreshToken)-5:])
	}

	return session, nil
}

func (storage *SessionStorage) SaveSession(session *server.Session) {

	storage.sessionsByAccessToken[session.AccessToken.Token] = session

	if session.RefreshToken != nil {

		storage.sessionsByRefreshToken[session.RefreshToken.Token] = session
	}
}

func (storage *SessionStorage) DeleteSession(session *server.Session) {

	delete(storage.sessionsByAccessToken, session.AccessToken.Token)
	delete(storage.sessionsByRefreshToken, session.RefreshToken.Token)
}

func (storage *SessionStorage) isExpired(token *server.Token) bool {

	return token == nil || (token.Expires != server.NoExpiration && token.Expires < int(time.Now().UTC().Unix()))
}

func NewSessionStorage() *SessionStorage {

	return &SessionStorage{
		make(map[string]*server.Session),
		make(map[string]*server.Session),
	}
}

type ScopeStorage struct {
	scopes map[string]*server.Scope
}

func (storage *ScopeStorage) FindScopeByName(name string) (*server.Scope, error) {

	scope, ok := storage.scopes[name]

	if !ok {
		return nil, fmt.Errorf("Scope named %s not found", name)
	}

	return scope, nil
}

func (storage *ScopeStorage) Set(name string, scope *server.Scope) *ScopeStorage {

	storage.scopes[name] = scope
	return storage
}

func NewScopeStorage() *ScopeStorage {

	return &ScopeStorage{
		make(map[string]*server.Scope),
	}
}
