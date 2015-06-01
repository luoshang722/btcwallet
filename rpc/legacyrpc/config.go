package legacyrpc

type Options struct {
	Username string
	Password string

	MaxPOSTClients      int64
	MaxWebsocketClients int64
}
