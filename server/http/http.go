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

func (request *RequestFormOauthSessionRequest) Get(name string) (string, bool) {

	request.parseRequestForm()

	return request.request.Form.Get(name), true
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
