package option

type StatsAPIServiceOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	AuthToken string `json:"auth_token,omitempty"`
}
