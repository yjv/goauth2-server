package server

import (
	"errors"
)

type Grant interface {
	GenerateSession(oauthSessionRequest OauthSessionRequest) (*Session, error)
	Name() string
	AccessTokenExpiration() int64
	SetServer(server *Server)
	ShouldGenerateRefreshToken(session *Session) bool
}

type PostProcessingGrant interface {
	Grant
	ProcessSession(*Session)
}

type BaseGrant struct {
	accessTokenExpiration int64
	server                *Server
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

func (grant *BaseGrant) ShouldGenerateRefreshToken(session *Session) bool {

	return false
}

type ClientCredentialsGrant struct {
	BaseGrant
}

func (grant *ClientCredentialsGrant) GenerateSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	client, error := AuthenticateClient(oauthSessionRequest, grant.server.ClientStorage())

	if client == nil {

		return nil, error
	}

	session := &Session{}
	session.Client = client
	session.Owner = NewOwnerFromClient(client)

	return session, nil
}

func (grant *ClientCredentialsGrant) Name() string {

	return "client_credentials"
}

type PasswordGrant struct {
	BaseGrant
}

func (grant *PasswordGrant) GenerateSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	var client *Client

	if client, error := AuthenticateClient(oauthSessionRequest, grant.server.ClientStorage()); client == nil {

		return nil, error
	}

	session := &Session{}
	session.Client = client

	username, exists := oauthSessionRequest.Get("username")

	if !exists {

		return nil, errors.New("username must be set")
	}

	password, exists := oauthSessionRequest.Get("password")

	if !exists {

		return nil, errors.New("password must be set")
	}

	var owner *Owner

	if owner, error := grant.server.OwnerStorage().FindByOwnerUsernameAndPassword(username, password); owner == nil {

		return nil, error
	}

	session.Owner = owner

	return session, nil
}

func (grant *PasswordGrant) Name() string {

	return "password"
}

func (grant *PasswordGrant) ShouldGenerateRefreshToken(session *Session) bool {

	return true
}

type RefreshTokenGrant struct {
	BaseGrant
	RotateRefreshTokens bool
}

func (grant *RefreshTokenGrant) GenerateSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	client, error := AuthenticateClient(oauthSessionRequest, grant.server.ClientStorage())

	if client == nil {

		return nil, error
	}

	refreshToken, exists := oauthSessionRequest.Get("refresh_token")

	if !exists {

		return nil, errors.New("refresh_token must be set")
	}

	session, error := grant.server.SessionStorage().FindByRefreshToken(refreshToken)

	if session == nil {

		return nil, error
	}

	session.AccessToken = nil

	if grant.RotateRefreshTokens {

		session.RefreshToken = nil
	}

	return session, nil
}

func (grant *RefreshTokenGrant) Name() string {

	return "refresh_token"
}

func (grant *RefreshTokenGrant) ShouldGenerateRefreshToken(session *Session) bool {

	return grant.RotateRefreshTokens
}

func (grant *RefreshTokenGrant) SetServer(server *Server) {

	grant.server = server
	server.Config().AllowRefresh = true
}

func AuthenticateClient(oauthSessionRequest OauthSessionRequest, storage ClientStorage) (*Client, error) {

	clientId, exists := oauthSessionRequest.Get("client_id")

	if !exists {

		return nil, errors.New("client_id must be set")
	}

	clientSecret, exists := oauthSessionRequest.Get("client_secret")

	if !exists {

		return nil, errors.New("client_secret must be set")
	}

	return storage.FindByClientIdAndSecret(clientId, clientSecret)
}
