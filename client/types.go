package client

import (
	"crypto/sha256"
	"encoding/json"
)

type TokenBinding struct {
	Status string `json:"status"` //can be "supported" or "present"
	Id     string `json:"id"`
}

type CollectedClientData struct {
	Type         string        `json:"type"`        //This member contains the string "webauthn.create" when creating new credentials, and "webauthn.get"
	Challenge    string        `json:"challenge"`   //This member contains the base64url encoding of the challenge provided by the Relying Party. Challenges SHOULD therefore be at least 16 bytes long.
	Origin       string        `json:"origin"`      //This member contains the fully qualified origin of the requester, as provided to the authenticator by the client, in the syntax defined by [RFC6454].
	CrossOrigin  bool          `json:"crossOrigin"` //This member contains the inverse of the sameOriginWithAncestors argument value that was passed into the internal method.
	TokenBinding *TokenBinding `json:"tokenBinding"`
}

func (c *CollectedClientData) ToHash() ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	res := sha256.Sum256(b)
	return res[:], nil

}
