package option

type TrojanInboundOptions struct {
	ListenOptions
	Users []TrojanUser       `json:"users,omitempty"`
	Auth  *TrojanAuthOptions `json:"auth,omitempty"`
	InboundTLSOptionsContainer
	Fallback        *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex       *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport       *V2RayTransportOptions    `json:"transport,omitempty"`
}

type TrojanAuthOptions struct {
	Mode string `json:"mode,omitempty"`
	API  string `json:"api,omitempty"`
}

type TrojanUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type TrojanOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string      `json:"password"`
	Network  NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions    `json:"transport,omitempty"`
}
