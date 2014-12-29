package server

import (
	"fmt"
)

type Grant interface {
	GenerateSession(oauthSessionRequest OauthSessionRequest, server Server) (*Session, error)
	Name() string
	AccessTokenExpiration() int
	ShouldGenerateRefreshToken(session *Session) bool
}

type PostProcessingGrant interface {
	Grant
	ProcessSession(session *Session)
}

type BaseGrant struct {
	accessTokenExpiration int
}

func (grant *BaseGrant) AccessTokenExpiration() int {

	return grant.accessTokenExpiration
}

func (grant *BaseGrant) ShouldGenerateRefreshToken(session *Session) bool {

	return false
}

type ClientCredentialsGrant struct {
	BaseGrant
}

func (grant *ClientCredentialsGrant) GenerateSession(oauthSessionRequest OauthSessionRequest, server Server) (*Session, error) {

	client, error := AuthenticateClient(oauthSessionRequest, server.ClientStorage())

	if client == nil {

		return nil, error
	}

	session := NewSession()
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

func (grant *PasswordGrant) GenerateSession(oauthSessionRequest OauthSessionRequest, server Server) (*Session, error) {

	client, error := AuthenticateClient(oauthSessionRequest, server.ClientStorage())

	if client == nil {

		return nil, error
	}

	session := NewSession()
	session.Client = client

	username, exists := oauthSessionRequest.GetFirst("username")

	if !exists {

		return nil, &RequiredValueMissingError{"username"}
	}

	password, exists := oauthSessionRequest.GetFirst("password")

	if !exists {

		return nil, &RequiredValueMissingError{"password"}
	}

	owner, error := server.OwnerStorage().FindOwnerByUsernameAndPassword(username, password)

	if owner == nil {

		return nil, &StorageSearchFailedError{"owner", error}
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
	RefreshOwner bool
}

func (grant *RefreshTokenGrant) GenerateSession(oauthSessionRequest OauthSessionRequest, server Server) (*Session, error) {

	client, error := AuthenticateClient(oauthSessionRequest, server.ClientStorage())

	if client == nil {
		return nil, error
	}

	refreshToken, exists := oauthSessionRequest.GetFirst("refresh_token")

	if !exists {
		return nil, &RequiredValueMissingError{"refresh_token"}
	}

	session, error := server.SessionStorage().FindSessionByRefreshToken(refreshToken)

	if session == nil {
		return nil, &StorageSearchFailedError{"session", error}
	}

	if session.Client.Id != client.Id {
		return nil, &StorageSearchFailedError{"session", fmt.Errorf(
			"client id %s on sessoin did not match client id %s found with client credentials",
			session.Client.Id,
			client.Id,
		)}
	}

	session.Client = client

	if grant.RefreshOwner {

		owner, error := server.OwnerStorage().RefreshOwner(session.Owner)

		if owner == nil {
			return nil, &StorageSearchFailedError{"owner", error}
		}

		session.Owner = owner
	}

	//make sure the requested scopes are already in the session. Cant add new scopes.
	//Actual instantiation of the scopes will happen in the server
	for _, scopeName := range oauthSessionRequest.Get("scopes") {
		_, ok := session.Scopes[scopeName]

		if !ok {
			return nil, &InvalidScopeError{scopeName, nil}
		}
	}

	//clear scopes so only the request scopes are assigned
	session.Scopes = make(map[string]*Scope)
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

func AuthenticateClient(oauthSessionRequest OauthSessionRequest, storage ClientStorage) (*Client, error) {

	clientId, exists := oauthSessionRequest.GetFirst("client_id")

	if !exists {

		return nil, &RequiredValueMissingError{"client_id"}
	}

	clientSecret, exists := oauthSessionRequest.GetFirst("client_secret")

	if !exists {

		return nil, &RequiredValueMissingError{"client_secret"}
	}

	client, error := storage.FindClientByIdAndSecret(clientId, clientSecret)

	if client == nil {

		return nil, &StorageSearchFailedError{"client", error}
	}

	return client, nil
}
