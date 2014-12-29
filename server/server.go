package server

type Server interface {
	GetGrant(name string) (Grant, bool)
	TokenGenerator() TokenGenerator
	ClientStorage() ClientStorage
	OwnerStorage() OwnerStorage
	SessionStorage() SessionStorage
	ScopeStorage() ScopeStorage
	Config() *Config
	GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, OauthError)
}

type DefaultServer struct {
	config         *Config
	grants         map[string]Grant
	tokenGenerator TokenGenerator
	clientStorage  ClientStorage
	ownerStorage   OwnerStorage
	sessionStorage SessionStorage
	scopeStorage   ScopeStorage
}

func (server *DefaultServer) AddGrant(grant Grant) *DefaultServer {

	server.grants[grant.Name()] = grant
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

func (server *DefaultServer) ScopeStorage() ScopeStorage {

	return server.scopeStorage
}

func (server *DefaultServer) Config() *Config {

	return server.config
}

func (server *DefaultServer) GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, OauthError) {

	grant, ok := server.GetGrant(oauthSessionRequest.Grant())

	if !ok {

		return nil, &GrantNotFoundError{oauthSessionRequest.Grant()}
	}

	session, error := grant.GenerateSession(oauthSessionRequest, server)

	if session == nil {

		var returnedError OauthError
		var ok bool

		if returnedError, ok = error.(OauthError); !ok {

			returnedError = &UnexpectedError{error}
		}

		return nil, returnedError
	}

	if session.AccessToken == nil {

		session.AccessToken = server.tokenGenerator.GenerateAccessToken(server.Config(), grant)
	}

	if server.config.AllowRefresh && grant.ShouldGenerateRefreshToken(session) {

		session.RefreshToken = server.tokenGenerator.GenerateRefreshToken(server.Config(), grant)
	}

	for _, scopeName := range oauthSessionRequest.Get("scopes") {

		scope, error := server.ScopeStorage().FindScopeByName(scopeName)

		if scope == nil {
			return nil, &InvalidScopeError{scopeName, error}
		}

		session.Scopes[scopeName] = scope
	}

	if v, ok := grant.(PostProcessingGrant); ok {

		v.ProcessSession(session)
	}

	go server.sessionStorage.SaveSession(session)

	return session, nil
}

func New(clientStorage ClientStorage, ownerStorage OwnerStorage, sessionStorage SessionStorage, scopeStorage ScopeStorage) *DefaultServer {

	return NewWithConfigAndTokenGenerator(
		NewConfig(),
		NewDefaultTokenGenerator(),
		clientStorage,
		ownerStorage,
		sessionStorage,
		scopeStorage,
	)
}

func NewWithTokenGenerator(
	tokenGenerator TokenGenerator,
	clientStorage ClientStorage,
	ownerStorage OwnerStorage,
	sessionStorage SessionStorage,
	scopeStorage ScopeStorage,
) *DefaultServer {

	return NewWithConfigAndTokenGenerator(
		NewConfig(),
		tokenGenerator,
		clientStorage,
		ownerStorage,
		sessionStorage,
		scopeStorage,
	)
}

func NewWithConfigAndTokenGenerator(
	config *Config,
	tokenGenerator TokenGenerator,
	clientStorage ClientStorage,
	ownerStorage OwnerStorage,
	sessionStorage SessionStorage,
	scopeStorage ScopeStorage,
) *DefaultServer {

	return &DefaultServer{
		config,
		make(map[string]Grant),
		tokenGenerator,
		clientStorage,
		ownerStorage,
		sessionStorage,
		scopeStorage,
	}
}
