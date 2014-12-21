package server

import (
	"fmt"
)

type Server interface {
	GetGrant(name string) (Grant, bool)
	TokenGenerator() TokenGenerator
	ClientStorage() ClientStorage
	OwnerStorage() OwnerStorage
	SessionStorage() SessionStorage
	Config() *Config
	GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, error)
}

type DefaultServer struct {
	config         *Config
	grants         map[string]Grant
	tokenGenerator TokenGenerator
	clientStorage  ClientStorage
	ownerStorage   OwnerStorage
	sessionStorage SessionStorage
}

func (server *DefaultServer) AddGrant(grant Grant) *DefaultServer {

	server.grants[grant.Name()] = grant
	grant.SetServer(server)

	return server
}

func (server *DefaultServer) GetGrant(name string) (Grant, bool) {

	grant, ok := server.grants[name]
	return grant, ok
}

func (server *DefaultServer) Grants() map[string]Grant {

	return server.grants
}

func (server *DefaultServer) TokenGenerator() TokenGenerator {

	return server.tokenGenerator
}

func (server *DefaultServer) ClientStorage() ClientStorage {

	return server.clientStorage
}

func (server *DefaultServer) OwnerStorage() OwnerStorage {

	return server.ownerStorage
}

func (server *DefaultServer) SessionStorage() SessionStorage {

	return server.sessionStorage
}

func (server *DefaultServer) Config() *Config {

	return server.config
}

func (server *DefaultServer) GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	grant, ok := server.GetGrant(oauthSessionRequest.Grant())

	if !ok {

		return nil, fmt.Errorf("grant named %s couldnt be found", oauthSessionRequest.Grant())
	}

	session, error := grant.GenerateSession(oauthSessionRequest)

	if session == nil {

		return nil, error
	}

	if session.AccessToken == nil {

		session.AccessToken = server.tokenGenerator.GenerateAccessToken(server.config, grant)
	}

	if server.config.AllowRefresh && grant.ShouldGenerateRefreshToken(session) {

		session.RefreshToken = server.tokenGenerator.GenerateRefreshToken(server.config, grant)
	}

	if v, ok := grant.(PostProcessingGrant); ok {

		v.ProcessSession(session)
	}

	go server.sessionStorage.Save(session)

	return session, nil
}

func NewServer(clientStorage ClientStorage, ownerStorage OwnerStorage, sessionStorage SessionStorage) *DefaultServer {

	return NewServerWithConfigAndTokenGenerator(
		NewConfig(),
		NewDefaultTokenGenerator(),
		clientStorage,
		ownerStorage,
		sessionStorage,
	)
}

func NewServerWithTokenGenerator(
	tokenGenerator TokenGenerator,
	clientStorage ClientStorage,
	ownerStorage OwnerStorage,
	sessionStorage SessionStorage,
) *DefaultServer {

	return NewServerWithConfigAndTokenGenerator(
		NewConfig(),
		tokenGenerator,
		clientStorage,
		ownerStorage,
		sessionStorage,
	)
}

func NewServerWithConfig(
	config *Config,
	clientStorage ClientStorage,
	ownerStorage OwnerStorage,
	sessionStorage SessionStorage,
) *DefaultServer {

	return NewServerWithConfigAndTokenGenerator(
		config,
		NewDefaultTokenGenerator(),
		clientStorage,
		ownerStorage,
		sessionStorage,
	)
}

func NewServerWithConfigAndTokenGenerator(
	config *Config,
	tokenGenerator TokenGenerator,
	clientStorage ClientStorage,
	ownerStorage OwnerStorage,
	sessionStorage SessionStorage,
) *DefaultServer {

	return &DefaultServer{
		config,
		make(map[string]Grant),
		tokenGenerator,
		clientStorage,
		ownerStorage,
		sessionStorage,
	}
}
