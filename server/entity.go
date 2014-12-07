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

type AccessTokenRequest interface {
	Grant() string
	Get(key string) (string, bool)
}

type BasicAccessTokenRequest struct {
	grant string
	data  map[string]string
}

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

func NewBasicAccessTokenRequest(grant string, data map[string]string) *BasicAccessTokenRequest {

	newData := make(map[string]string)

	for key, value := range data {

		newData[key] = value
	}

	return &BasicAccessTokenRequest{grant, newData}
}

func (request *BasicAccessTokenRequest) Get(name string) (string, bool) {

	val, ok := request.data[name]
	return val, ok
}

func (request *BasicAccessTokenRequest) Grant() string {

	return request.grant
}

func OwnerFromClient(client *Client) *Owner {

	return &Owner{client.Id, client.Name}
}
