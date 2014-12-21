package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewConfig(t *testing.T) {

	assert.Equal(t, &Config{
		3600,   //1 hour
		604800, //1 week
		false,
	}, NewConfig())
}
