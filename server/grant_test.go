package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"errors"
)

func TestClientCredentialsGrant(t *testing.T) {

	grant := &ClientCredentialsGrant{BaseGrant{123, nil}}
	assert.Equal(t, "client_credentials", grant.Name())
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.False(t, grant.ShouldGenerateRefreshToken(&Session{}))
}

func TestClientCredentialsGrantGenerateSession(t *testing.T) {

	grant := &ClientCredentialsGrant{BaseGrant{123, nil}}
	server := &MockServer{}
	grant.SetServer(server)
	client, params, _ := runClientLoadAssertions(t, grant, server)
	session := &Session{}
	session.Client = client
	session.Owner = NewOwnerFromClient(client)
	generatedSession, error := grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})
	assert.Equal(t, session, generatedSession)
	assert.Nil(t, error)
}

func TestPasswordGrant(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123, nil}}
	assert.Equal(t, "password", grant.Name())
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.True(t, grant.ShouldGenerateRefreshToken(&Session{}))
}

func TestPasswordGrantGenerateSession(t *testing.T) {

	grant := &PasswordGrant{BaseGrant{123, nil}}
	server := &MockServer{}
	grant.SetServer(server)
	client, params, storage := runClientLoadAssertions(t, grant, server)

	//username missing
	session, error := grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})
	assert.Nil(t, session)
	assert.Equal(t, errors.New("username must be set"), error)

	params["username"] = "username"

	//password missing
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})
	assert.Nil(t, session)
	assert.Equal(t, errors.New("password must be set"), error)

	params["password"] = "password"

	server.On("OwnerStorage").Return(storage)
	storage.On("FindByOwnerUsernameAndPassword", params["username"], params["password"]).Return(nil, errors.New("error"))

	//owner failed to load
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})
	assert.Nil(t, session)
	assert.Equal(t, errors.New("error"), error)

	owner := &Owner{
		"id",
		"name",
	}

	params["username"] = "right_username"
	storage.On("FindByOwnerUsernameAndPassword", params["username"], params["password"]).Return(owner, nil)

	expectedSession := &Session{}
	expectedSession.Client = client
	expectedSession.Owner = owner

	//client loads
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)
}

func TestRefreshGrant(t *testing.T) {

	grant := &RefreshTokenGrant{BaseGrant{123, nil}, false}
	assert.Equal(t, "refresh_token", grant.Name())
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.False(t, grant.ShouldGenerateRefreshToken(&Session{}))
	grant.RotateRefreshTokens = true
	assert.True(t, grant.ShouldGenerateRefreshToken(&Session{}))
}

func TestRefreshGrantGenerateSession(t *testing.T) {

	grant := &RefreshTokenGrant{}
	server := &MockServer{}
	config := NewConfig()
	server.On("Config").Return(config)
	grant.SetServer(server)
	assert.True(t, config.AllowRefresh)
	client, params, _ := runClientLoadAssertions(t, grant, server)

	//refresh_token missing
	session, error := grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})
	assert.Nil(t, session)
	assert.Equal(t, errors.New("refresh_token must be set"), error)

	params["refresh_token"] = "refresh_token"

	storage := &MockSessionStorage{}
	server.On("SessionStorage").Return(storage)
	storage.On("FindByRefreshToken", params["refresh_token"]).Return(nil, errors.New("error"))

	//owner failed to load
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})
	assert.Nil(t, session)
	assert.Equal(t, errors.New("error"), error)

	owner := &Owner{
		"id",
		"name",
	}

	client = &Client{
		"id",
		"name",
		"redirect_uri",
	}

	params["refresh_token"] = "good_refresh_token"

	expectedSession := &Session{}
	expectedSession.Client = client
	expectedSession.Owner = owner
	expectedSession.RefreshToken = &Token{}
	returnedSession := &(*expectedSession)
	storage.On("FindByRefreshToken", params["refresh_token"]).Return(returnedSession, nil)

	//session loads
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)

	expectedSession.RefreshToken = nil
	grant.RotateRefreshTokens = true

	//session loads
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grant.Name(), params})

	assert.Equal(t, expectedSession, session)
	assert.Nil(t, error)
}

func runClientLoadAssertions(t *testing.T, grant Grant, server *MockServer) (*Client, map[string]string, *MockOwnerClientStorage) {

	storage := &MockOwnerClientStorage{}
	server.On("ClientStorage").Return(storage)

	//no client id
	session, error := grant.GenerateSession(&BasicOauthSessionRequest{})
	assert.Nil(t, session)
	assert.Equal(t, &OauthError{"client_id must be set"}, error)

	params := make(map[string]string)
	grantName := grant.Name()

	params["client_id"] = "client_id"

	//no client secret
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grantName, params})
	assert.Nil(t, session)
	assert.Equal(t, &OauthError{"client_secret must be set"}, error)

	params["client_secret"] = "client_secret"

	storage.On("FindByClientIdAndSecret", params["client_id"], params["client_secret"]).Return(nil, errors.New("error"))

	//client failed to load
	session, error = grant.GenerateSession(&BasicOauthSessionRequest{grantName, params})
	assert.Nil(t, session)
	assert.Equal(t, errors.New("error"), error)

	client := &Client{
		"client_id",
		"name",
		"redirect_uri",
	}

	params["client_id"] = "good_client_id"

	storage.On("FindByClientIdAndSecret", params["client_id"], params["client_secret"]).Return(client, nil)

	return client, params, storage
}
