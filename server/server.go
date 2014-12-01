package server

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/base64"
	"fmt"
	"time"
)


type TokenIdGeneratorFunc func() string

type TokenGenerator interface {
	GenerateToken(serverConfig *Config) (*Token, error)
}

func GenerateTokenId() string {

	token := uuid.New()
	token = base64.StdEncoding.EncodeToString([]byte(token))
	return token
}

type Config struct {

	DefaultAccessTokenExpires int64
	DefaultRefreshTokenExpires int64
	AllowRefresh bool
	TokenIdGenerator TokenIdGeneratorFunc
	ClientStorage ClientStorage
	OwnerStorage OwnerStorage
	SessionStorage SessionStorage
}

type Server struct {

	Config *Config
	grants map[string]Grant
}

func NewServer(config *Config) *Server {

	return &Server{
		config,
		make(map[string]Grant),
	}
}

func NewConfig(clientStorage ClientStorage, ownerStorage OwnerStorage, sessionStorage SessionStorage) *Config {

	return &Config{
		3600, //1 hour
		604800, //1 week
		false,
		GenerateTokenId,
		clientStorage,
		ownerStorage,
		sessionStorage,
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

		return nil, fmt.Errorf("The grant %q was not found", name);
	}

	grant := server.grants[name]
	return grant, nil
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

		session.AccessToken = server.generateToken(grant, AccessToken)
	}

	if server.Config.AllowRefresh && grant.SessionRefreshable(session) {

		session.RefreshToken = server.generateToken(grant, RefreshToken)
	}

	if v, ok := grant.(PostProcessingGrant); ok {

		v.ProcessSession(session)
	}

	go server.Config.SessionStorage.Save(session)

	return session, nil
}

func (server *Server) generateToken(grant Grant, tokenType TokenType) *Token {

	var expiration int64

	if tokenType == AccessToken {

		expiration = grant.AccessTokenExpiration()

		if expiration == 0 {

			expiration = server.Config.DefaultAccessTokenExpires
		}
	} else {

		expiration = server.Config.DefaultRefreshTokenExpires
	}

	return &Token{
		server.Config.TokenIdGenerator(),
		time.Now().UTC().Add(time.Duration(expiration) * time.Second).Unix(),
	}
}
