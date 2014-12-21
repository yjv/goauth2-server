package server

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestServerGettersAndGrantManagement(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	config := NewConfig()
	tokenGenerator := NewDefaultTokenGenerator()

	server := NewServerWithConfigAndTokenGenerator(
		config,
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	assert.Equal(t, server, server.AddGrant(grant))
	returnedGrant, ok := server.GetGrant("test")
	assert.True(t, ok)
	assert.Equal(t, grant, returnedGrant)
	returnedGrant, ok = server.GetGrant("hello")
	assert.False(t, ok)
	grants := make(map[string]Grant)
	grants["test"] = grant
	assert.Equal(t, grants, server.Grants())
	assert.Equal(t, ownerClientStorage, server.ClientStorage())
	assert.Equal(t, ownerClientStorage, server.OwnerStorage())
	assert.Equal(t, sessionStorage, server.SessionStorage())
	assert.Equal(t, config, server.Config())
	assert.Equal(t, tokenGenerator, server.TokenGenerator())
}

func TestServerGrantOauthSessionWhereGrantNotFound(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}

	server := NewServer(
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	server.AddGrant(grant)

	session, error := server.GrantOauthSession(NewBasicOauthSessionRequest("bla", make(map[string]string)))

	assert.Nil(t, session)
	assert.Equal(t, errors.New("grant named bla couldnt be found"), error)
}

func TestServerGrantOauthSessionWhereGrantReturnsAnError(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}

	server := NewServer(
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)
	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(nil, errors.New("bla bla bla"))
	server.AddGrant(grant)

	session, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Nil(t, session)
	assert.Equal(t, errors.New("bla bla bla"), error)
}

func TestServerGrantOauthSessionWhereGrantReturnsASessionWithAnAccessToken(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	tokenGenerator := &MockTokenGenerator{}

	server := NewServerWithTokenGenerator(
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)

	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	session := &Session{}
	session.AccessToken = &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(session, nil)
	server.AddGrant(grant)

	sessionStorage.On("Save", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Nil(t, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsASessionWithAnAccessTokenAndGrantIsProcessingGrant(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	tokenGenerator := &MockTokenGenerator{}

	server := NewServerWithTokenGenerator(
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)

	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	session := &Session{}
	session.AccessToken = &Token{}
	grant := &MockProcessingGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(session, nil)
	grant.On("ProcessSession", session).Return()
	server.AddGrant(grant)

	sessionStorage.On("Save", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Nil(t, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsASessionWithoutAnAccessToken(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	tokenGenerator := &MockTokenGenerator{}

	server := NewServerWithTokenGenerator(
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)

	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	session := &Session{}
	token := &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(session, nil)
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(token)
	sessionStorage.On("Save", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Equal(t, token, returnedSession.AccessToken)
	assert.Nil(t, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsASessionWithoutAnAccessTokenAndRefreshTokenAllowedButGrantDoesntAllow(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	tokenGenerator := &MockTokenGenerator{}

	server := NewServerWithTokenGenerator(
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)

	server.Config().AllowRefresh = true

	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	session := &Session{}
	accessToken := &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(session, nil)
	grant.On("ShouldGenerateRefreshToken", session).Return(false)
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(accessToken)
	sessionStorage.On("Save", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Equal(t, accessToken, returnedSession.AccessToken)
	assert.Nil(t, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsASessionWithoutAnAccessTokenAndRefreshTokenAllowedButAndGrantAllows(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	tokenGenerator := &MockTokenGenerator{}

	server := NewServerWithTokenGenerator(
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)

	server.Config().AllowRefresh = true

	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	session := &Session{}
	accessToken := &Token{}
	refreshToken := &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(session, nil)
	grant.On("ShouldGenerateRefreshToken", session).Return(true)
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(accessToken)
	tokenGenerator.On("GenerateRefreshToken", server.Config(), grant).Return(refreshToken)
	sessionStorage.On("Save", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Equal(t, accessToken, returnedSession.AccessToken)
	assert.Equal(t, refreshToken, returnedSession.RefreshToken)
	assert.Nil(t, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsASessionWithoutAnAccessTokenAndRefreshTokenAllowedButAndGrantAllowsAndGrantIsProcessingGrant(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}
	tokenGenerator := &MockTokenGenerator{}

	server := NewServerWithTokenGenerator(
		tokenGenerator,
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)

	server.Config().AllowRefresh = true

	oauthSessionRequest := NewBasicOauthSessionRequest("test", make(map[string]string))
	session := &Session{}
	accessToken := &Token{}
	refreshToken := &Token{}
	grant := &MockProcessingGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest).Return(session, nil)
	grant.On("ShouldGenerateRefreshToken", session).Return(true)
	grant.On("ProcessSession", session).Return()
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(accessToken)
	tokenGenerator.On("GenerateRefreshToken", server.Config(), grant).Return(refreshToken)
	sessionStorage.On("Save", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Equal(t, accessToken, returnedSession.AccessToken)
	assert.Equal(t, refreshToken, returnedSession.RefreshToken)
	assert.Nil(t, error)
}

type MockOwnerClientStorage struct {
	mock.Mock
}

func (storage *MockOwnerClientStorage) FindClientByClientId(clientId string) (*Client, error) {

	args := storage.Mock.Called(clientId)
	return args.Get(0).(*Client), args.Error(1)
}

func (storage *MockOwnerClientStorage) FindByClientIdAndSecret(clientId string, clientSecret string) (*Client, error) {

	args := storage.Mock.Called(clientId, clientSecret)
	return args.Get(0).(*Client), args.Error(1)
}
func (storage *MockOwnerClientStorage) FindByOwnerUsername(username string) (*Owner, error) {

	args := storage.Mock.Called(username)
	return args.Get(0).(*Owner), args.Error(1)
}

func (storage *MockOwnerClientStorage) FindByOwnerUsernameAndPassword(username string, password string) (*Owner, error) {

	args := storage.Mock.Called(username, password)
	return args.Get(0).(*Owner), args.Error(1)
}

type MockSessionStorage struct {
	mock.Mock
}

func (storage *MockSessionStorage) FindByAccessToken(accessToken string) (*Session, error) {

	args := storage.Mock.Called(accessToken)
	return args.Get(0).(*Session), args.Error(1)
}

func (storage *MockSessionStorage) FindByRefreshToken(refreshToken string) (*Session, error) {

	args := storage.Mock.Called(refreshToken)
	return args.Get(0).(*Session), args.Error(1)
}

func (storage *MockSessionStorage) Save(session *Session) {

	storage.Mock.Called(session)
}

func (storage *MockSessionStorage) Delete(session *Session) {

	storage.Mock.Called(session)
}

type MockGrant struct {
	mock.Mock
	Server Server
}

func (grant *MockGrant) GenerateSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	args := grant.Mock.Called(oauthSessionRequest)
	session, _ := args.Get(0).(*Session)
	return session, args.Error(1)
}

func (grant *MockGrant) Name() string {

	return grant.Mock.Called().Get(0).(string)
}

func (grant *MockGrant) AccessTokenExpiration() int64 {

	return grant.Mock.Called().Get(0).(int64)
}

func (grant *MockGrant) SetServer(server Server) {

	grant.Server = server
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
