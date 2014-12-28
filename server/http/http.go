package http

import (
	"net/http"
)

type RequestFormOauthSessionRequest struct {
	request *http.Request
}

func NewRequestFormOauthSessionRequest(request *http.Request) *RequestFormOauthSessionRequest {

	return &RequestFormOauthSessionRequest{request}
}

func (request *RequestFormOauthSessionRequest) Get(name string) []string {

	request.parseRequestForm()
	value, ok := request.request.Form[name]

	if !ok {
		return []string{}
	}

	return value
}

func (request *RequestFormOauthSessionRequest) GetFirst(name string) (string, bool) {

	request.parseRequestForm()
	_, ok := request.request.Form[name]
	return request.request.Form.Get(name), ok
}

func (request *RequestFormOauthSessionRequest) Grant() string {

	request.parseRequestForm()
	return request.request.Form.Get("grant")
}

func (request *RequestFormOauthSessionRequest) parseRequestForm() {

	err := request.ParseForm()

	if err != nil {

		panic("The request params couldnt be parsed")
	}
}
