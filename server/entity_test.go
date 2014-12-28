package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

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
