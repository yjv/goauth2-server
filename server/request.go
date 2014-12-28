package server

type OauthSessionRequest interface {
	Grant() string
	GetFirst(key string) (string, bool)
	Get(key string) []string
}

type BasicOauthSessionRequest struct {
	grant string
	data  map[string][]string
}

func NewBasicOauthSessionRequest(grant string) *BasicOauthSessionRequest {

	return &BasicOauthSessionRequest{grant, make(map[string][]string)}
}

func (request *BasicOauthSessionRequest) GetFirst(name string) (string, bool) {

	val := request.Get(name)

	if len(val) == 0 {

		return "", false
	}

	return val[0], true
}

func (request *BasicOauthSessionRequest) Get(name string) []string {

	val, ok := request.data[name]

	if !ok {

		val = []string{}
	}

	return val
}

func (request *BasicOauthSessionRequest) Grant() string {

	return request.grant
}

func (request *BasicOauthSessionRequest) Set(key string, value string) *BasicOauthSessionRequest {

	request.data[key] = []string{value}
	return request
}

func (request *BasicOauthSessionRequest) SetAll(values map[string]string) *BasicOauthSessionRequest {

	for key, value := range values {
		request.Set(key, value)
	}

	return request
}

func (request *BasicOauthSessionRequest) Add(key string, value string) *BasicOauthSessionRequest {

	if _, ok := request.data[key]; !ok {

		request.data[key] = []string{}
	}

	request.data[key] = append(request.data[key], value)
	return request
}

func (request *BasicOauthSessionRequest) AddAll(key string, values []string) *BasicOauthSessionRequest {

	for _, value := range values {
		request.Add(key, value)
	}

	return request
}

func (request *BasicOauthSessionRequest) Delete(key string) *BasicOauthSessionRequest {

	delete(request.data, key)
	return request
}
