package server

import (
	"fmt"
)

type Server struct {
	config         *Config
	grants         map[string]Grant
	tokenGenerator TokenGenerator
	clientStorage  ClientStorage
	ownerStorage   OwnerStorage
	sessionStorage SessionStorage
}

func (server *Server) AddGrant(grant Grant) *Server {

	server.grants[grant.Name()] = grant
	grant.SetServer(server)

	return server
}

func (server *Server) GetGrant(name string) (Grant, bool) {

	grant, ok := server.grants[name]
	return grant, ok
}

func (server *Server) Grants() map[string]Grant {

	return server.grants
}

func (server *Server) TokenGenerator() TokenGenerator {

	return server.tokenGenerator
}

func (server *Server) ClientStorage() ClientStorage {

	return server.clientStorage
}

func (server *Server) OwnerStorage() OwnerStorage {

	return server.ownerStorage
}

func (server *Server) SessionStorage() SessionStorage {

	return server.sessionStorage
}

func (server *Server) Config() *Config {

	return server.config
}

func (server *Server) GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

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

func NewServer(clientStorage ClientStorage, ownerStorage OwnerStorage, sessionStorage SessionStorage) *Server {

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
) *Server {

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
) *Server {

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
) *Server {

	return &Server{
		config,
		make(map[string]Grant),
		tokenGenerator,
		clientStorage,
		ownerStorage,
		sessionStorage,
	}
}


