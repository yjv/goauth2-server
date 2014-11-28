package oauth2server

type Client struct {
	Id string
	Name string
	RedirectUri string
}

type Owner struct {
	Id string
	Name string
}

type Token struct {
	Token string
	Expires int64
}

type AuthCode struct {

}

type Session struct {
	AccessToken Token
	RefreshToken Token
	AuthCode AuthCode
	Scopes []string
	ClientId string
	OwnerId string
	ExtraData map[string]string
}

type AccessTokenRequest interface {

	Grant() string
	Get(key string) (string, bool)
}

type BasicAccessTokenRequest struct {

	grant string
	data map[string]string
}

func NewBasicAccessTokenRequest(grant string, data map[string]string) *BasicAccessTokenRequest {

	newData := make(map[string]string)

	for key, value := range data {

		newData[key] = value
	}

	return &AccessTokenRequest(grant, newData)
}

func (request *BasicAccessTokenRequest) Get(name string) (string, bool) {

	return request.data[name]
}

func (request *BasicAccessTokenRequest) Grant() string {

	return request.grant
}
