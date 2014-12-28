package server

import (
	"errors"
	"github.com/stretchr/testify/assert"
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

	session, error := server.GrantOauthSession(NewBasicOauthSessionRequest("bla"))

	assert.Nil(t, session)
	assert.Equal(t, &GrantNotFoundError{"bla"}, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsAnError(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}

	server := NewServer(
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)
	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(nil, errors.New("bla bla bla"))
	server.AddGrant(grant)

	session, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Nil(t, session)
	assert.Equal(t, &UnexpectedError{errors.New("bla bla bla")}, error)
}

func TestServerGrantOauthSessionWhereGrantReturnsAnOauthError(t *testing.T) {

	ownerClientStorage := &MockOwnerClientStorage{}
	sessionStorage := &MockSessionStorage{}

	server := NewServer(
		ownerClientStorage,
		ownerClientStorage,
		sessionStorage,
	)
	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(nil, &RequiredValueMissingError{"value"})
	server.AddGrant(grant)

	session, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Nil(t, session)
	assert.Equal(t, &RequiredValueMissingError{"value"}, error)
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

	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	session := &Session{}
	session.AccessToken = &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(session, nil)
	server.AddGrant(grant)

	sessionStorage.On("SaveSession", session).Return()

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

	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	session := &Session{}
	session.AccessToken = &Token{}
	grant := &MockProcessingGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(session, nil)
	grant.On("ProcessSession", session).Return()
	server.AddGrant(grant)

	sessionStorage.On("SaveSession", session).Return()

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

	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	session := &Session{}
	token := &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(session, nil)
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(token)
	sessionStorage.On("SaveSession", session).Return()

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

	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	session := &Session{}
	accessToken := &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(session, nil)
	grant.On("ShouldGenerateRefreshToken", session).Return(false)
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(accessToken)
	sessionStorage.On("SaveSession", session).Return()

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

	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	session := &Session{}
	accessToken := &Token{}
	refreshToken := &Token{}
	grant := &MockGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(session, nil)
	grant.On("ShouldGenerateRefreshToken", session).Return(true)
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(accessToken)
	tokenGenerator.On("GenerateRefreshToken", server.Config(), grant).Return(refreshToken)
	sessionStorage.On("SaveSession", session).Return()

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

	oauthSessionRequest := NewBasicOauthSessionRequest("test")
	session := &Session{}
	accessToken := &Token{}
	refreshToken := &Token{}
	grant := &MockProcessingGrant{}
	grant.On("Name").Return("test")
	grant.On("GenerateSession", oauthSessionRequest, server).Return(session, nil)
	grant.On("ShouldGenerateRefreshToken", session).Return(true)
	grant.On("ProcessSession", session).Return()
	server.AddGrant(grant)
	tokenGenerator.On("GenerateAccessToken", server.Config(), grant).Return(accessToken)
	tokenGenerator.On("GenerateRefreshToken", server.Config(), grant).Return(refreshToken)
	sessionStorage.On("SaveSession", session).Return()

	returnedSession, error := server.GrantOauthSession(oauthSessionRequest)

	assert.Equal(t, session, returnedSession)
	assert.Equal(t, accessToken, returnedSession.AccessToken)
	assert.Equal(t, refreshToken, returnedSession.RefreshToken)
	assert.Nil(t, error)
}
