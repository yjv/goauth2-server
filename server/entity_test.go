package server

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestBasicOauthSessionRequest(t *testing.T) {

	grant := "grant"
	data := make(map[string]string)
	data["key"] = "value"
	data["key1"] = "value1"
	request := NewBasicOauthSessionRequest(grant, data)

	assert.Equal(t, grant, request.Grant())

	value1, _ := request.Get("key")

	assert.Equal(t, data["key"], value1)

	value2, ok := request.Get("key1")

	assert.Equal(t, data["key1"], value2)

	_, ok = request.Get("key2")

	assert.False(t, ok)
}

func TestOwnerFromClient(t *testing.T) {

	client := &Client{
		"id",
		"name",
		"redirectUri",
	}

	assert.Equal(t, &Owner{
		"id",
		"name",
	}, NewOwnerFromClient(client))
}
