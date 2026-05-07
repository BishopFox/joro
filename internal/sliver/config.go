package sliver

// OperatorConfig holds the Sliver operator config file fields.
type OperatorConfig struct {
	Operator      string `json:"operator"`
	LHost         string `json:"lhost"`
	LPort         int    `json:"lport"`
	Token         string `json:"token"`
	CACertificate string `json:"ca_certificate"`
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"private_key"`
}
