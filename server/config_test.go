package server

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {

	assert.Equal(t, &Config{
		3600,   //1 hour
		604800, //1 week
		false,
	}, NewConfig())
}
