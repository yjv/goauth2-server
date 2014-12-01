package oauth2server

import (
	"errors"
)

type Grant interface {
	AuthenticateAccessRequest(accessTokenRequest AccessTokenRequest, session *Session) (bool, bool, error)
	Name() string
	AccessTokenExpiration() int64
	SetServer(server *Server)
}

type PostProcessingGrant interface {
	Grant
	ProcessSession(*Session)
}

type BaseGrant struct {
	accessTokenExpiration int64
	server *Server
}

func (grant *BaseGrant) AccessTokenExpiration() int64 {

	return grant.accessTokenExpiration
}

func (grant *BaseGrant) SetAccessTokenExpiration(expiration int64) *BaseGrant {

	grant.accessTokenExpiration = expiration
	return grant
}

func (grant *BaseGrant) SetServer(server *Server) {

	grant.server = server
}

type ClientCredentialsGrant struct {
	BaseGrant
}

func (grant *ClientCredentialsGrant) AuthenticateAccessRequest(accessTokenRequest AccessTokenRequest, session *Session) (bool, bool, error) {

	client, error := authenticateClient(accessTokenRequest, grant.server.Config.ClientStorage)

	if client == nil {

		return false, false, error
	}

	session.Client = client
	session.Owner = OwnerFromClient(client)

	if error != nil {

		return false, false, error
	}

	return true, false, nil
}

func (grant *ClientCredentialsGrant) Name() string {

	return "client_credentials"
}

type PasswordGrant struct {
	BaseGrant
}

func (grant *PasswordGrant) AuthenticateAccessRequest(accessTokenRequest AccessTokenRequest, session *Session) (bool, bool, error) {

	var client *Client

	if client, error := authenticateClient(accessTokenRequest, grant.server.Config.ClientStorage); client == nil {

		return false, false, error
	}

	session.Client = client

	username, exists := accessTokenRequest.Get("username");

	if !exists {

		return false, false, errors.New("username must be set")
	}

	password, exists := accessTokenRequest.Get("password")

	if !exists {

		return false, false, errors.New("password must be set")
	}

	var owner *Owner

	if owner, error := grant.server.Config.OwnerStorage.FindByOwnerUsernameAndPassword(username, password); owner == nil {

		return false, false, error
	}

	session.Owner = owner

	return true, true, nil
}

func (grant *PasswordGrant) Name() string {

	return "password"
}

type RefreshTokenGrant struct {
	BaseGrant
	RotateRefreshTokens bool
}

func (grant *RefreshTokenGrant) AuthenticateAccessRequest(accessTokenRequest AccessTokenRequest, session *Session) (bool, bool, error) {

	client, error := authenticateClient(accessTokenRequest, grant.server.Config.ClientStorage)

	if client == nil {

		return false, false, error
	}

	refreshToken, exists := accessTokenRequest.Get("refresh_token");

	if !exists {

		return false, false, errors.New("refresh_token must be set")
	}

	oldSession, error := grant.server.Config.SessionStorage.FindByRefreshToken(refreshToken)

	if oldSession == nil {

		return false, false, error
	}

	*session = *oldSession

	session.AccessToken = nil

	if (grant.RotateRefreshTokens) {

		session.RefreshToken = nil
	}

	return true, grant.RotateRefreshTokens, nil
}

func (grant *RefreshTokenGrant) Name() string {

	return "refresh_token"
}

func (grant *RefreshTokenGrant) SetServer(server *Server) {

	grant.server = server
	server.Config.AllowRefresh = true
}

func authenticateClient(accessTokenRequest AccessTokenRequest, storage ClientStorage) (*Client, error) {

	clientId, exists := accessTokenRequest.Get("client_id");

	if !exists {

		return nil, errors.New("client_id must be set")
	}

	clientSecret, exists := accessTokenRequest.Get("client_secret")

	if !exists {

		return nil, errors.New("client_secret must be set")
	}

	return storage.FindByClientIdAndSecret(clientId, clientSecret)
}
