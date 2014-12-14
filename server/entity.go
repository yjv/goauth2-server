package server

type Client struct {
	Id          string
	Name        string
	RedirectUri string
}

type Owner struct {
	Id   string
	Name string
}

type Token struct {
	Token   string
	Expires int64
}

const (
	NoExpiration int64 = -1
)

type AuthCode struct {
}

type Session struct {
	Id           string
	AccessToken  *Token
	RefreshToken *Token
	AuthCode     *AuthCode
	Scopes       []string
	Client       *Client
	Owner        *Owner
	ExtraData    map[string]string
}

type OauthSessionRequest interface {
	Grant() string
	Get(key string) (string, bool)
}

type BasicOauthSessionRequest struct {
	grant string
	data  map[string]string
}

func NewBasicOauthSessionRequest(grant string, data map[string]string) *BasicOauthSessionRequest {

	newData := make(map[string]string)

	for key, value := range data {

		newData[key] = value
	}

	return &BasicOauthSessionRequest{grant, newData}
}

func (request *BasicOauthSessionRequest) Get(name string) (string, bool) {

	val, ok := request.data[name]
	return val, ok
}

func (request *BasicOauthSessionRequest) Grant() string {

	return request.grant
}

func NewOwnerFromClient(client *Client) *Owner {

	return &Owner{client.Id, client.Name}
}
