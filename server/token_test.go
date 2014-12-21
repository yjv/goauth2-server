package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewDefaultTokenGenerator(t *testing.T) {

	generator := &DefaultTokenGenerator{GenerateTokenId}
	assert.Equal(t, generator, NewDefaultTokenGenerator())
}

func TestDefaultTokenGeneratorGenerateAccessTokenWithGrantNotReturningExpiration(t *testing.T) {

	generator := NewDefaultTokenGeneratorWithGeneratorFunc(GeneratorFuncMock)
	config := NewConfig()
	config.DefaultAccessTokenExpires = 2
	token := generator.GenerateAccessToken(config, &TestGrant{})
	assert.Equal(t, &Token{
		"hello",
		time.Now().UTC().Add(time.Duration(2) * time.Second).Unix(),
	}, token)
}

func TestDefaultTokenGeneratorGenerateAccessTokenWithGrantReturningExpiration(t *testing.T) {

	generator := NewDefaultTokenGeneratorWithGeneratorFunc(GeneratorFuncMock)
	config := NewConfig()
	config.DefaultAccessTokenExpires = 2
	token := generator.GenerateAccessToken(config, &TestGrant{nil, nil, 5, true, nil})
	assert.Equal(t, &Token{
		"hello",
		time.Now().UTC().Add(time.Duration(5) * time.Second).Unix(),
	}, token)
}

func TestDefaultTokenGeneratorGenerateRefreshToken(t *testing.T) {

	generator := NewDefaultTokenGeneratorWithGeneratorFunc(GeneratorFuncMock)
	config := NewConfig()
	config.DefaultRefreshTokenExpires = 2
	token := generator.GenerateRefreshToken(config, &TestGrant{})
	assert.Equal(t, &Token{
		"hello",
		time.Now().UTC().Add(time.Duration(2) * time.Second).Unix(),
	}, token)
}

func GeneratorFuncMock() string {

	return "hello"
}

type TestGrant struct {
	Session                         *Session
	Error                           error
	AccessTokenExpirationValue      int64
	ShouldGenerateRefreshTokenValue bool
	Server                          Server
}

func (grant *TestGrant) GenerateSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	return grant.Session, grant.Error
}

func (grant *TestGrant) Name() string {

	return "test"
}

func (grant *TestGrant) AccessTokenExpiration() int64 {

	return grant.AccessTokenExpirationValue
}

func (grant *TestGrant) SetServer(server Server) {

	grant.Server = server
}

func (grant *TestGrant) ShouldGenerateRefreshToken(session *Session) bool {

	return grant.ShouldGenerateRefreshTokenValue
}
