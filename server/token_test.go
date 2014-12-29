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
	grant := &MockGrant{}
	grant.On("AccessTokenExpiration").Return(0)
	token := generator.GenerateAccessToken(config, grant)
	assert.Equal(t, &Token{
		"hello",
		int(time.Now().UTC().Add(time.Duration(2) * time.Second).Unix()),
	}, token)
}

func TestDefaultTokenGeneratorGenerateAccessTokenWithGrantReturningExpiration(t *testing.T) {

	generator := NewDefaultTokenGeneratorWithGeneratorFunc(GeneratorFuncMock)
	config := NewConfig()
	config.DefaultAccessTokenExpires = 2
	grant := &MockGrant{}
	grant.On("AccessTokenExpiration").Return(5)
	token := generator.GenerateAccessToken(config, grant)
	assert.Equal(t, &Token{
		"hello",
		int(time.Now().UTC().Add(time.Duration(5) * time.Second).Unix()),
	}, token)
}

func TestDefaultTokenGeneratorGenerateRefreshToken(t *testing.T) {

	generator := NewDefaultTokenGeneratorWithGeneratorFunc(GeneratorFuncMock)
	config := NewConfig()
	config.DefaultRefreshTokenExpires = 2
	grant := &MockGrant{}
	grant.On("AccessTokenExpiration").Return(0)
	token := generator.GenerateRefreshToken(config, grant)
	assert.Equal(t, &Token{
		"hello",
		int(time.Now().UTC().Add(time.Duration(2) * time.Second).Unix()),
	}, token)
}

func GeneratorFuncMock() string {

	return "hello"
}
