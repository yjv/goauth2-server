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
	Expires int
}

type Scope struct {
	Id   string
	Name string
}

const (
	NoExpiration int = -1
)

type AuthCode struct {
}

type Session struct {
	Id           string
	AccessToken  *Token
	RefreshToken *Token
	AuthCode     *AuthCode
	Scopes       map[string]*Scope
	Client       *Client
	Owner        *Owner
	ExtraData    map[string]string
}

func NewSession() *Session {
	session := &Session{}
	session.Scopes = make(map[string]*Scope)
	session.ExtraData = make(map[string]string)
	return session
}

func NewOwnerFromClient(client *Client) *Owner {

	return &Owner{client.Id, client.Name}
}
