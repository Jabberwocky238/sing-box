package option

type AuthOptions struct {
	Mode               string `json:"mode,omitempty"`
	API                string `json:"api,omitempty"`
	CacheExpirySeconds int    `json:"cache_expiry_seconds,omitempty"`
}
