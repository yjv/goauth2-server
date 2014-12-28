package server

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/base64"
	"time"
)

type TokenIdGeneratorFunc func() string

func GenerateTokenId() string {

	return base64.StdEncoding.EncodeToString([]byte(uuid.New()))
}

type TokenGenerator interface {
	GenerateAccessToken(serverConfig *Config, grant Grant) *Token
	GenerateRefreshToken(serverConfig *Config, grant Grant) *Token
}

type DefaultTokenGenerator struct {
	tokenIdGenerator TokenIdGeneratorFunc
}

func (generator *DefaultTokenGenerator) GenerateAccessToken(config *Config, grant Grant) *Token {

	var expiration int

	expiration = grant.AccessTokenExpiration()

	if expiration == 0 {

		expiration = config.DefaultAccessTokenExpires
	}

	return &Token{
		generator.tokenIdGenerator(),
		int(time.Now().UTC().Add(time.Duration(expiration) * time.Second).Unix()),
	}
}

func (generator *DefaultTokenGenerator) GenerateRefreshToken(config *Config, grant Grant) *Token {

	var expiration int

	expiration = config.DefaultRefreshTokenExpires

	return &Token{
		generator.tokenIdGenerator(),
		int(time.Now().UTC().Add(time.Duration(expiration) * time.Second).Unix()),
	}
}

func (generator *DefaultTokenGenerator) TokenIdGenerator() TokenIdGeneratorFunc {

	return generator.tokenIdGenerator
}

func NewDefaultTokenGenerator() *DefaultTokenGenerator {

	return &DefaultTokenGenerator{GenerateTokenId}
}

func NewDefaultTokenGeneratorWithGeneratorFunc(generatorFunc TokenIdGeneratorFunc) *DefaultTokenGenerator {

	return &DefaultTokenGenerator{generatorFunc}
}
