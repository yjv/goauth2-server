package server

type Config struct {
	DefaultAccessTokenExpires  int
	DefaultRefreshTokenExpires int
	AllowRefresh               bool
}

func NewConfig() *Config {

	return &Config{
		3600,   //1 hour
		604800, //1 week
		false,
	}
}
