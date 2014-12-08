package server

type Config struct {
	DefaultAccessTokenExpires  int64
	DefaultRefreshTokenExpires int64
	AllowRefresh               bool
}

func NewConfig() *Config {

	return &Config{
		3600,   //1 hour
		604800, //1 week
		false,
	}
}
