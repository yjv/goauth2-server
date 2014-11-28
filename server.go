package oauth2server

import (
	"errors"
)

type Config struct {

	DefaultAccessTokenExpires int64
	DefaultRefreshTokenExpires int64
	RotateRefreshTokens bool
}

func NewConfig(DefaultAccessTokenExpires int64, DefaultRefreshTokenExpires int64, RotateRefreshTokens bool) (*Config) {

	return &Config{DefaultAccessTokenExpires, DefaultRefreshTokenExpires, RotateRefreshTokens}
}

type Server struct {

	Config *Config
	grants map[string]*Grant
}

func NewServer(config *Config) (*Server) {

	return &Server{config, make(map[string]*Grant)}
}

func (server *Server) AddGrant(grant *Grant) (*Server) {

	server.grants[grant.Name()] = grant
	return server
}

func (server *Server) HasGrant(name string) (bool) {

	_, ok := server.grants[name]
	return ok
}

func (server *Server) GetGrant(name string) (*Grant, error) {

	if !server.HasGrant(name) {

		return errors.New("The grant was not found");
	}

	grant := server.grants[name]
	return grant, nil
}

func (*Server) GrantAccessToken() (*AccessToken, error, *Session) {


}
