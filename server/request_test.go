package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicOauthSessionRequest(t *testing.T) {

	grant := "grant"
	data := make(map[string]string)
	data["key"] = "value"
	data["key1"] = "value1"
	request := NewBasicOauthSessionRequest(grant).SetAll(data)
	assert.Equal(t, grant, request.Grant())

	value1, _ := request.GetFirst("key")

	assert.Equal(t, data["key"], value1)
	assert.Equal(t, []string{data["key"]}, request.Get("key"))

	value2, ok := request.GetFirst("key1")

	assert.Equal(t, data["key1"], value2)

	_, ok = request.GetFirst("key2")

	assert.False(t, ok)
	assert.Equal(t, []string{}, request.Get("key2"))
	assert.Equal(t, []string{data["key1"], "value2"}, request.Add("key1", "value2").Get("key1"))
	assert.Equal(t, []string{"value3"}, request.Add("key2", "value3").Get("key2"))
	assert.Equal(t, []string{"value", "value4", "value5"}, request.AddAll("key", []string{"value4", "value5"}).Get("key"))
	assert.Equal(t, []string{}, request.Delete("key").Get("key"))
	_, ok = request.GetFirst("key")

	assert.False(t, ok)
}
