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
	AccessToken *Token
	RefreshToken *Token
	AuthCode *AuthCode
	Scopes []string
	Client *Client
	Owner *Owner
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

type TokenType string

const (
	AccessToken TokenType = "access"
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

func CopySession(source *Session) *Session {

	destination := &Session{}
	destination.AccessToken = source.AccessToken
	destination.RefreshToken = source.RefreshToken
	destination.AuthCode = source.AuthCode
	destination.Scopes = make([]string, len(source.Scopes))

	for key := range source.Scopes {

		destination.Scopes[key] = source.Scopes[key]
	}

	destination.Client = source.Client
	destination.Owner = source.Owner

	destination.ExtraData = make(map[string]string)

	for key := range source.ExtraData {

		destination.ExtraData[key] = source.ExtraData[key]
	}

	return destination
}
