package server

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/base64"
	"fmt"
	"time"
)

type TokenIdGeneratorFunc func() string

func GenerateTokenId() string {

	token := uuid.New()
	token = base64.StdEncoding.EncodeToString([]byte(token))
	return token
}

type TokenGenerator interface {
	GenerateAccessToken(serverConfig *Config, grant Grant) *Token
	GenerateRefreshToken(serverConfig *Config, grant Grant) *Token
}

type Config struct {
	DefaultAccessTokenExpires  int64
	DefaultRefreshTokenExpires int64
	AllowRefresh               bool
}

type Server struct {
	config         *Config
	grants         map[string]Grant
	tokenGenerator TokenGenerator
	clientStorage  ClientStorage
	ownerStorage   OwnerStorage
	sessionStorage SessionStorage
}

func NewServer(clientStorage ClientStorage, ownerStorage OwnerStorage, sessionStorage SessionStorage) *Server {

	return NewServerWithTokenGenerator(
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

	return &Server{
		NewConfig(),
		make(map[string]Grant),
		tokenGenerator,
		clientStorage,
		ownerStorage,
		sessionStorage,
	}
}

func NewConfig() *Config {

	return &Config{
		3600,   //1 hour
		604800, //1 week
		false,
	}
}

func (server *Server) AddGrant(grant Grant) *Server {

	server.grants[grant.Name()] = grant
	grant.SetServer(server)

	return server
}

func (server *Server) HasGrant(name string) bool {

	_, ok := server.grants[name]
	return ok
}

func (server *Server) GetGrant(name string) (Grant, error) {

	if !server.HasGrant(name) {

		return nil, fmt.Errorf("The grant %q was not found", name)
	}

	grant := server.grants[name]
	return grant, nil
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

func (server *Server) GrantOauthSession(accessTokenRequest AccessTokenRequest) (*Session, error) {

	grant, error := server.GetGrant(accessTokenRequest.Grant())

	if grant == nil {

		return nil, error
	}

	session, error := grant.GenerateSession(accessTokenRequest)

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

type DefaultTokenGenerator struct {
	tokenIdGenerator TokenIdGeneratorFunc
}

func (generator *DefaultTokenGenerator) GenerateAccessToken(config *Config, grant Grant) *Token {

	var expiration int64

	expiration = grant.AccessTokenExpiration()

	if expiration == 0 {

		expiration = config.DefaultAccessTokenExpires
	}

	return &Token{
		generator.tokenIdGenerator(),
		time.Now().UTC().Add(time.Duration(expiration) * time.Second).Unix(),
	}
}

func (generator *DefaultTokenGenerator) GenerateRefreshToken(config *Config, grant Grant) *Token {

	var expiration int64

	expiration = config.DefaultRefreshTokenExpires

	return &Token{
		generator.tokenIdGenerator(),
		time.Now().UTC().Add(time.Duration(expiration) * time.Second).Unix(),
	}
}

func (generator *DefaultTokenGenerator) TokenIdGenerator() TokenIdGeneratorFunc {

	return generator.tokenIdGenerator
}

func NewDefaultTokenGenerator() *DefaultTokenGenerator {

	return &DefaultTokenGenerator{GenerateTokenId}
}
