package fido2

import (
	"encoding/base64"
	"encoding/json"
)

type ClientData struct {
	Type        string `json:"type"`        // "webauthn.create" or "webauthn.get"
	Challenge   string `json:"challenge"`   // the fun part for signing requests
	Origin      string `json:"origin"`      // the origin of the request
	CrossOrigin bool   `json:"crossOrigin"` //defaults to false
}

func (c *ClientData) ToB64() []byte {
	//Encode it to JsonString
	j, _ := json.Marshal(c)
	//Encode it Base64
	b64 := base64.StdEncoding.EncodeToString(j)
	//hash it SHA256
	return []byte(b64)
}
