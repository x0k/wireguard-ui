package model

import (
	"time"
)

// Server model
type Server struct {
	KeyPair   *ServerKeypair
	Interface *ServerInterface
}

// ServerKeypair model
type ServerKeypair struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ServerInterface model
type ServerInterface struct {
	Addresses []string `json:"addresses"`
	// ,string to get listen_port string input as int
	ListenPort int       `json:"listen_port,string"`
	UpdatedAt  time.Time `json:"updated_at"`
	PostUp     string    `json:"post_up"`
	PreDown    string    `json:"pre_down"`
	PostDown   string    `json:"post_down"`
	AmneziaWGProperties
}

// AmneziaWGProperties model
type AmneziaWGProperties struct {
	Jc   int    `json:"jc,string,omitempty"`
	Jmin int    `json:"jmin,string,omitempty"`
	Jmax int    `json:"jmax,string,omitempty"`
	S1   int    `json:"s1,string,omitempty"`
	S2   int    `json:"s2,string,omitempty"`
	S3   int    `json:"s3,string,omitempty"`
	S4   int    `json:"s4,string,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}
