package option

// AuthOptions enables external authentication on an inbound.
type AuthOptions struct {
	// Mode: "http" posts {"auth","addr","tx"} to API and expects {"ok","id"}.
	Mode               string `json:"mode,omitempty"`
	API                string `json:"api,omitempty"`
	CacheExpirySeconds int    `json:"cache_expiry_seconds,omitempty"`
}

type StatsAPIServiceOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	AuthToken string `json:"auth_token,omitempty"`
}
