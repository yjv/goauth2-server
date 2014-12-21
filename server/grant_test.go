package server

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestClientCredentialsGrantGrant(t *testing.T) {

	grant := &ClientCredentialsGrant{BaseGrant{123, nil}}
	server := &MockServer{}
	grant.SetServer(server)
	runBaseGrantAssertions(t, grant)
}

func runBaseGrantAssertions(t *testing.T, grant Grant) {
	assert.Equal(t, grant.AccessTokenExpiration(), 123)
	assert.False(t, grant.ShouldGenerateRefreshToken(&Session{}))
}

type MockServer struct {
	mock.Mock
	Server
}

func (server *MockServer) GetGrant(name string) (Grant, bool) {

	args := server.Mock.Called(name)
	grant, _ := args.Get(0).(Grant)
	return grant, args.Bool(1)
}

func (server *MockServer) TokenGenerator() TokenGenerator {

	args := server.Mock.Called()
	tokenGenerator, _ := args.Get(0).(TokenGenerator)
	return tokenGenerator
}

func (server *MockServer) ClientStorage() ClientStorage {

	args := server.Mock.Called()
	storage, _ := args.Get(0).(ClientStorage)
	return storage
}

func (server *MockServer) OwnerStorage() OwnerStorage {

	args := server.Mock.Called()
	storage, _ := args.Get(0).(OwnerStorage)
	return storage
}

func (server *MockServer) SessionStorage() SessionStorage {

	args := server.Mock.Called()
	storage, _ := args.Get(0).(SessionStorage)
	return storage
}

func (server *MockServer) Config() *Config {

	args := server.Mock.Called()
	config, _ := args.Get(0).(*Config)
	return config
}

func (server *MockServer) GrantOauthSession(oauthSessionRequest OauthSessionRequest) (*Session, error) {

	args := server.Mock.Called(oauthSessionRequest)
	session, _ := args.Get(0).(*Session)
	return session, args.Error(1)

}
