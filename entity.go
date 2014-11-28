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

type AccessToken struct {

	Token string
	ClientId string
	OwnerId string
	Expires int64
	Scopes []string
	ExtraData map[string]string
}
type RefreshToken struct {

	Token string
	ClientId string
	OwnerId string
	Expires int64
	Scopes []string
	ExtraData map[string]string
}

type Session struct {

	AccessToken AccessToken
	RefreshToken RefreshToken
}
