package server

type OauthError struct {
	string string
}

func (error *OauthError) Error() string {
	return error.string
}
