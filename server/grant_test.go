package server

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClientCredentialsGrant(t *testing.T) {

	grant := &ClientCredentialsGrant{BaseGrant{123}}
	assert.Equal(t, "client_credentials", grant.Name())
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.False(t, grant.ShouldGenerateRefreshToken(NewSession()))
}

func TestClientCredentialsGrantGenerateSession(t *testing.T) {

	grant := &ClientCredentialsGrant{BaseGrant{123}}
	server := &MockServer{}
	client, request, _ := runClientLoadAssertions(t, grant, server)
	session := NewSession()
	session.Client = client
	session.Owner = NewOwnerFromClient(client)
	generatedSession, error := grant.GenerateSession(request, server)
	assert.Equal(t, session, generatedSession)
	assert.Nil(t, error)
}

func TestPasswordGrant(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123}}
	assert.Equal(t, "password", grant.Name())
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.True(t, grant.ShouldGenerateRefreshToken(NewSession()))
}

func TestPasswordGrantGenerateSessionWithUsernameMissing(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123}}
	server := &MockServer{}
	_, request, _ := runClientLoadAssertions(t, grant, server)

	//username missing
	session, error := grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &RequiredValueMissingError{"username"}, error)
}

func TestPasswordGrantGenerateSessionWithPasswordMissing(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123}}
	server := &MockServer{}
	_, request, _ := runClientLoadAssertions(t, grant, server)

	request.Set("username", "username")

	//password missing
	session, error := grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &RequiredValueMissingError{"password"}, error)
}

func TestPasswordGrantGenerateSessionWhereOwnerFailedToLoad(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123}}
	server := &MockServer{}
	_, request, storage := runClientLoadAssertions(t, grant, server)

	request.Set("username", "username")
	request.Set("password", "password")

	server.On("OwnerStorage").Return(storage)
	storage.On("FindOwnerByUsernameAndPassword", "username", "password").Return(nil, errors.New("error"))

	//owner failed to load
	session, error := grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &StorageSearchFailedError{"owner", errors.New("error")}, error)
}

func TestPasswordGrantGenerateSessionWhereAllGood(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123}}
	server := &MockServer{}
	client, request, storage := runClientLoadAssertions(t, grant, server)

	request.Set("username", "username")
	request.Set("password", "password")

	server.On("OwnerStorage").Return(storage)

	owner := &Owner{
		"id",
		"name",
	}

	request.Set("username", "right_username")
	storage.On("FindOwnerByUsernameAndPassword", "right_username", "password").Return(owner, nil)

	expectedSession := NewSession()
	expectedSession.Client = client
	expectedSession.Owner = owner

	//client loads
	session, error := grant.GenerateSession(request, server)

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)
}

func TestRefreshGrant(t *testing.T) {

	grant := &RefreshTokenGrant{BaseGrant{123}, false, false}
	assert.Equal(t, "refresh_token", grant.Name())
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.False(t, grant.ShouldGenerateRefreshToken(NewSession()))
	grant.RotateRefreshTokens = true
	assert.True(t, grant.ShouldGenerateRefreshToken(NewSession()))
}

func TestRefreshGrantGenerateSession(t *testing.T) {

	grant := &RefreshTokenGrant{}
	server := &MockServer{}
	config := NewConfig()
	server.On("Config").Return(config)
	client, request, clientOwnerStorage := runClientLoadAssertions(t, grant, server)

	//refresh_token missing
	session, error := grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &RequiredValueMissingError{"refresh_token"}, error)

	request.Set("refresh_token", "refresh_token")

	storage := &MockSessionStorage{}
	server.On("SessionStorage").Return(storage)
	storage.On("FindSessionByRefreshToken", "refresh_token").Return(nil, errors.New("error"))

	//owner failed to load
	session, error = grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &StorageSearchFailedError{"session", errors.New("error")}, error)

	request.Set("refresh_token", "good_refresh_token")

	returnedSession := NewSession()
	returnedSession.Client = &Client{
		"id2",
		"name",
		"redr",
	}
	returnedSession.Owner = &Owner{
		"id",
		"name",
	}
	returnedSession.RefreshToken = &Token{}
	storage.On("FindSessionByRefreshToken", "good_refresh_token").Return(returnedSession, nil).Times(1)

	//session loads but clients dont match
	session, error = grant.GenerateSession(request, server)

	assert.Nil(t, session)
	assert.IsType(t, &StorageSearchFailedError{}, error)

	returnedSession = NewSession()
	returnedSession.Client = client
	returnedSession.Owner = &Owner{
		"id",
		"name",
	}
	returnedSession.RefreshToken = &Token{}
	storage.On("FindSessionByRefreshToken", "good_refresh_token").Return(returnedSession, nil).Times(1)

	server.On("OwnerStorage").Return(clientOwnerStorage)

	clientOwnerStorage.On("RefreshOwner", returnedSession.Owner).Return(nil, errors.New("bad")).Times(1)

	grant.RefreshOwner = true

	//session loads but owner refresh fails
	session, error = grant.GenerateSession(request, server)

	assert.Nil(t, session)
	assert.Equal(t, &StorageSearchFailedError{"owner", errors.New("bad")}, error)

	expectedSession := NewSession()
	expectedSession.Client = client
	expectedSession.Owner = &Owner{
		"id",
		"name",
	}
	expectedSession.RefreshToken = &Token{}
	returnedSession = &(*expectedSession)

	storage.On("FindSessionByRefreshToken", "good_refresh_token").Return(returnedSession, nil).Times(1)
	clientOwnerStorage.On("RefreshOwner", returnedSession.Owner).Return(returnedSession.Owner, nil).Times(1)

	//session loads
	session, error = grant.GenerateSession(request, server)

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)

	grant.RefreshOwner = false

	expectedSession = NewSession()
	expectedSession.Client = client
	expectedSession.Owner = &Owner{
		"id",
		"name",
	}
	expectedSession.RefreshToken = &Token{}
	returnedSession = &(*expectedSession)

	storage.On("FindSessionByRefreshToken", "good_refresh_token").Return(returnedSession, nil)

	//session loads
	session, error = grant.GenerateSession(request, server)

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)

	expectedSession.RefreshToken = nil
	grant.RotateRefreshTokens = true

	//session loads and refresh token is rotated
	session, error = grant.GenerateSession(request, server)

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)

	returnedSession.Scopes["scope1"] = &Scope{}
	returnedSession.Scopes["scope3"] = &Scope{}
	request.AddAll("scopes", []string{"scope1", "scope2", "scope3"})

	//scopes not on session requested
	session, error = grant.GenerateSession(request, server)

	assert.Nil(t, session)
	assert.Equal(t, &InvalidScopeError{"scope2", nil}, error)

	returnedSession.Scopes["scope2"] = &Scope{}

	//scopes all on session requested
	session, error = grant.GenerateSession(request, server)

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)
}

func runClientLoadAssertions(t *testing.T, grant Grant, server *MockServer) (*Client, *BasicOauthSessionRequest, *MockOwnerClientStorage) {

	storage := &MockOwnerClientStorage{}
	server.On("ClientStorage").Return(storage)

	//no client id
	session, error := grant.GenerateSession(&BasicOauthSessionRequest{}, server)
	assert.Nil(t, session)
	assert.Equal(t, &RequiredValueMissingError{"client_id"}, error)

	request := NewBasicOauthSessionRequest(grant.Name())

	request.Set("client_id", "client_id")

	//no client secret
	session, error = grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &RequiredValueMissingError{"client_secret"}, error)

	request.Set("client_secret", "client_secret")

	storage.On("FindClientByIdAndSecret", "client_id", "client_secret").Return(nil, errors.New("error")).Times(1)

	//client failed to load
	session, error = grant.GenerateSession(request, server)
	assert.Nil(t, session)
	assert.Equal(t, &StorageSearchFailedError{"client", errors.New("error")}, error)

	client := &Client{
		"client_id",
		"name",
		"redirect_uri",
	}

	request.Set("client_secret", "client_secret")

	storage.On("FindClientByIdAndSecret", "client_id", "client_secret").Return(client, nil)

	return client, request, storage
}
