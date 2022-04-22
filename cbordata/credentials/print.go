package credentials

import "fmt"

func PrintAttestationObject(attest *AttestationObject) {
	fmt.Printf(
		`Attestation Object:
		Format: %s
		AuthData:
			rpIDHash: %x
			flags: %x
			counter: %d
			AttCredData:
				Aaguid: %x
				CredID: %x
				CredPubKey: 
					Kty: %d
					Alg: %d
					Crv: %d
					X: %x
					Y: %x
			Extensions:
				HmacSecret: %v
		AttStmt:
			alg: %d
			sig: %x
			x5c: %x
`,
		attest.Fmt,
		attest.AuthData.RpIdHash,
		attest.AuthData.Flags,
		attest.AuthData.Counter,
		attest.AuthData.AttCredData.Aaguid,
		attest.AuthData.AttCredData.CredID,
		attest.AuthData.AttCredData.CredPubKey.Kty,
		attest.AuthData.AttCredData.CredPubKey.Alg,
		attest.AuthData.AttCredData.CredPubKey.CrvOrNOrK,
		attest.AuthData.AttCredData.CredPubKey.XOrE,
		attest.AuthData.AttCredData.CredPubKey.Y,
		*attest.AuthData.Extensions.HmacSecret,
		attest.AttStmt.Alg,
		attest.AttStmt.Sig,
		attest.AttStmt.X5c)
}
