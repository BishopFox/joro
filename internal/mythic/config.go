package mythic

// Config holds the connection details for a Mythic C2 server.
//
// Two auth modes are supported:
//   - Username + Password: exchanged at POST /auth for a JWT access token.
//   - APIToken: sent directly as the "apitoken" header on every GraphQL call
//     (skips the /auth round-trip). Takes precedence when set.
type Config struct {
	URL      string `json:"url"`      // e.g. https://10.0.0.5:7443 (Mythic nginx)
	Username string `json:"username"` // for the /auth JWT flow
	Password string `json:"password"`
	APIToken string `json:"apiToken"` // alternative: apitoken header, skips /auth
}
