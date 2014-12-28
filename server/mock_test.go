package server

import (
	"github.com/stretchr/testify/mock"
)

type MockServer struct {
	mock.Mock
	Server
}

func (server *MockServer) GetGrant(name string) (Grant, bool) {

	args := server.Mock.Called(name)
	grant, _ := args.Get(0).(Grant)
	return grant, args.Bool(1)
}

func (server *MockServer) TokenGenerator() TokenGenerator {

	args := server.Mock.Called()
	tokenGenerator, _ := args.Get(0).(TokenGenerator)
	return tokenGenerator
}

func (server *MockServer) ClientStorage() ClientStorage {

	args := server.Mock.Called()
	storage, _ := args.Get(0).(ClientStorage)
	return storage
}

func (server *MockServer) OwnerStorage() OwnerStorage {

	args := server.Mock.Called()
	storage, _ := args.Get(0).(OwnerStorage)
	return storage
}

func (server *MockServer) SessionStorage() SessionStorage {

	args := server.Mock.Called()
	storage, _ := args.Get(0).(SessionStorage)
	return storage
}

func (server *MockServer) Config() *Config {

	args := server.Mock.Called()
	config, _ := args.Get(0).(*Config)
	return config
}

func (server *MockServer) GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, OauthError) {

	args := server.Mock.Called(oauthSessionRequest)
	session, _ := args.Get(0).(*Session)
	error, _ := args.Get(1).(OauthError)
	return session, error

}

type MockOwnerClientStorage struct {
	mock.Mock
}

func (storage *MockOwnerClientStorage) FindClientById(clientId string) (*Client, error) {

	args := storage.Mock.Called(clientId)
	client, _ := args.Get(0).(*Client)
	return client, args.Error(1)
}

func (storage *MockOwnerClientStorage) FindClientByIdAndSecret(clientId string, clientSecret string) (*Client, error) {

	args := storage.Mock.Called(clientId, clientSecret)
	client, _ := args.Get(0).(*Client)
	return client, args.Error(1)
}

func (storage *MockOwnerClientStorage) RefreshClient(client *Client) (*Client, error) {
	args := storage.Mock.Called(client)
	client, _ = args.Get(0).(*Client)
	return client, args.Error(1)

}

func (storage *MockOwnerClientStorage) FindOwnerByUsername(username string) (*Owner, error) {

	args := storage.Mock.Called(username)
	owner, _ := args.Get(0).(*Owner)
	return owner, args.Error(1)
}

func (storage *MockOwnerClientStorage) FindOwnerByUsernameAndPassword(username string, password string) (*Owner, error) {

	args := storage.Mock.Called(username, password)
	owner, _ := args.Get(0).(*Owner)
	return owner, args.Error(1)
}

func (storage *MockOwnerClientStorage) RefreshOwner(owner *Owner) (*Owner, error) {
	args := storage.Mock.Called(owner)
	owner, _ = args.Get(0).(*Owner)
	return owner, args.Error(1)

}

type MockSessionStorage struct {
	mock.Mock
}

func (storage *MockSessionStorage) FindSessionByAccessToken(accessToken string) (*Session, error) {

	args := storage.Mock.Called(accessToken)
	session, _ := args.Get(0).(*Session)
	return session, args.Error(1)
}

func (storage *MockSessionStorage) FindSessionByRefreshToken(refreshToken string) (*Session, error) {

	args := storage.Mock.Called(refreshToken)
	session, _ := args.Get(0).(*Session)
	return session, args.Error(1)
}

func (storage *MockSessionStorage) SaveSession(session *Session) {

	storage.Mock.Called(session)
}

func (storage *MockSessionStorage) DeleteSession(session *Session) {

	storage.Mock.Called(session)
}

type MockScopeStorage struct {
	mock.Mock
}

func (generator *MockScopeStorage) FindScopeByName(name string) (*Scope, error) {

	args := generator.Mock.Called(name)
	scope, _ := args.Get(0).(*Scope)
	return scope, args.Error(1)
}

type MockGrant struct {
	mock.Mock
	Server Server
}

func (grant *MockGrant) GenerateSession(oauthSessionRequest OauthSessionRequest, server Server) (*Session, error) {

	args := grant.Mock.Called(oauthSessionRequest, server)
	session, _ := args.Get(0).(*Session)
	return session, args.Error(1)
}

func (grant *MockGrant) Name() string {

	return grant.Mock.Called().Get(0).(string)
}

func (grant *MockGrant) AccessTokenExpiration() int {

	return grant.Mock.Called().Get(0).(int)
}


func (grant *MockGrant) ShouldGenerateRefreshToken(session *Session) bool {

	return grant.Mock.Called(session).Bool(0)
}

type MockProcessingGrant struct {
	MockGrant
}

func (grant *MockProcessingGrant) ProcessSession(session *Session) {

	grant.Mock.Called(session)
}

type MockTokenGenerator struct {
	mock.Mock
}

func (generator *MockTokenGenerator) GenerateAccessToken(config *Config, grant Grant) *Token {

	return generator.Mock.Called(config, grant).Get(0).(*Token)
}

func (generator *MockTokenGenerator) GenerateRefreshToken(config *Config, grant Grant) *Token {

	return generator.Mock.Called(config, grant).Get(0).(*Token)
}
